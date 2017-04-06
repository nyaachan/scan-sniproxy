// SNI proxy scanner.
//
// Usage: ./scan-sniproxy ADDR [ADDR...]
//
// Output format is CSV:
// date,target,host,port,sni,elapsed,is_sniproxy,spki_sha256,error
// "host" and "port" are the result of resolving "target".
// "spki_sha256" is a hex representation of the SHA-256 hash of the leaf
// certificate's Subject Public Key Info.

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const port = "443"

// What SNI to ask for (-servername flag).
var serverName = "sni-scan-for-research-study.bamsoftware.com"

// Number of parallel scanners (-maxthreads flag).
var maxThreads = 1000

// Dial timeout (-timeout flag).
var timeout time.Duration = 10 * time.Second

var csvWriter *csv.Writer
var csvMutex sync.Mutex

func csvWrite(record []string) {
	csvMutex.Lock()
	defer csvMutex.Unlock()
	err := csvWriter.Write(record)
	if err != nil {
		panic(err)
	}
}

func spkiHash(cert *x509.Certificate) []byte {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return digest[:]
}

func escape(s string) string {
	s = strconv.QuoteToASCII(s)
	return s[1 : len(s)-1]
}

func scan(target string) (*net.TCPAddr, *x509.Certificate, error) {
	var cert *x509.Certificate

	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(target, port))
	if err != nil {
		return addr, cert, err
	}

	dialer := net.Dialer{
		Timeout: timeout,
	}
	config := tls.Config{
		ServerName: serverName,
	}
	conn, err := tls.DialWithDialer(&dialer, addr.Network(), addr.String(), &config)
	if err == nil {
		peerCerts := conn.ConnectionState().PeerCertificates
		if len(peerCerts) > 0 {
			cert = peerCerts[0]
		}
		conn.Close()
	}

	return addr, cert, err
}

func scanAndLog(target string) {
	startTime := time.Now()
	addr, cert, err := scan(target)
	elapsedTime := time.Since(startTime).Seconds()

	record := struct {
		date, target, host, port, sni, elapsed, is_sniproxy, spki_sha256, error string
	}{
		date:        startTime.UTC().Format("2006-01-02 15:04:05.000"),
		target:      target,
		host:        "",
		port:        "",
		sni:         serverName,
		elapsed:     strconv.FormatFloat(elapsedTime, 'f', 3, 64),
		is_sniproxy: "",
		spki_sha256: "",
		error:       "",
	}
	if addr != nil {
		record.host = addr.IP.String()
		record.port = strconv.Itoa(addr.Port)
	}
	if cert != nil {
		record.spki_sha256 = hex.EncodeToString(spkiHash(cert))
	}
	if err == nil {
		record.is_sniproxy = "T"
	} else {
		record.is_sniproxy = "F"
		record.error = escape(err.Error())
	}

	csvWrite([]string{record.date, record.target, record.host, record.port, record.sni, record.elapsed, record.is_sniproxy, record.spki_sha256, record.error})
}

func readTargetsFromInputFile(r io.Reader, targetChan chan<- string) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		targetChan <- s.Text()
	}
	return s.Err()
}

func readTargetsFromInputFilename(filename string, targetChan chan<- string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return readTargetsFromInputFile(f, targetChan)
}

// Return true of the Go TLS library is going to consider the given host string
// as an IP address and ignore it.
// https://github.com/golang/go/blob/go1.7.1/src/crypto/tls/handshake_client.go#L744
func serverNameIsIP(host string) bool {
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	return net.ParseIP(host) != nil
}

func main() {
	var inputFilename string
	var maxProcs int

	flag.StringVar(&inputFilename, "input", "", "file containing addresses")
	flag.IntVar(&maxProcs, "maxprocs", runtime.GOMAXPROCS(0), "GOMAXPROCS setting")
	flag.IntVar(&maxThreads, "maxthreads", maxThreads, "number of scanner threads")
	flag.StringVar(&serverName, "servername", serverName, "SNI to request")
	flag.DurationVar(&timeout, "timeout", timeout, "connection timeout")
	flag.Parse()

	runtime.GOMAXPROCS(maxProcs)

	if maxThreads <= 0 {
		fmt.Fprintln(os.Stderr, "argument to -maxthreads must be at least 1")
		os.Exit(1)
	}

	// Go TLS will silently discard a requested SNI that is an IP address.
	// Raise an error so people don't try it, thinking it will work.
	if serverNameIsIP(serverName) {
		fmt.Fprintln(os.Stderr, "argument to -servername cannot be an IP address")
		os.Exit(1)
	}

	csvWriter = csv.NewWriter(os.Stdout)
	csvWrite([]string{"date", "target", "host", "port", "sni", "elapsed", "is_sniproxy", "spki_sha256", "error"})

	var wg sync.WaitGroup
	targetChan := make(chan string)
	for i := 0; i < maxThreads; i++ {
		wg.Add(1)
		go func() {
			for target := range targetChan {
				scanAndLog(target)
			}
			wg.Done()
		}()
	}
	if inputFilename != "" {
		err := readTargetsFromInputFilename(inputFilename, targetChan)
		if err != nil {
			panic(err)
		}
	}
	for _, target := range flag.Args() {
		targetChan <- target
	}
	close(targetChan)
	wg.Wait()

	csvWriter.Flush()
	err := csvWriter.Error()
	if err != nil {
		panic(err)
	}
}
