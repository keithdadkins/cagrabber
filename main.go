package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	// parse flags
	host := flag.String("host", "", "Host address to grab the certs from. Hostname or full `URL`")
	flag.Parse()
	if *host == "" {
		flag.Usage()
		os.Exit(0)
	}

	// handle proto
	if !strings.HasPrefix(*host, "https://") {
		if strings.HasPrefix(*host, "http://") {
			log.Fatal("Cannot use http protocol to retrieve certs. Did you mean to use https?")
		}
		*host = "https://" + *host
	}

	// Parse the url and check for errors
	hostURL, err := url.Parse(*host)
	if err != nil {
		log.Fatal(err)
	}

	// Handle port (hostURL.Port() returns a string)
	var port int
	switch hostURL.Port() {
	case "":
		port = 443
	default:
		port, err = strconv.Atoi(hostURL.Port())
		if err != nil {
			log.Fatal("Could not parse port. Please check the url.")
		}
	}

	// Build the url to call
	var hosturl string
	switch {
	case port == 443: // use default port
		hosturl = fmt.Sprintf("https://%s%s", hostURL.Hostname(), hostURL.Path)
	default: // use the port provided in the url
		hosturl = fmt.Sprintf("https://%s:%s%s", hostURL.Hostname(), hostURL.Port(), hostURL.Path)
	}

	// If the local machine does not trust the sites CA (the primary use case for this
	// utility) we will get an error, so skip it.
	tls := &tls.Config{
		InsecureSkipVerify: true,
	}

	// We want to peek TLS, so we need to define an http.Transport to use with our client.
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    tls,
	}

	// Connect to the host
	fmt.Printf("Grepping %s for CA certificates..\n", hostURL.Hostname())
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Get(hosturl)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// // print the certs to std.out in default DER format
	// fname := fmt.Sprintf("%s.ca.crt", hostURL.Hostname())
	// f, err := os.OpenFile(fname, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	// if err != nil {
	// 	log.Fatalf("could not open %s for writing", fname)
	// }
	// defer f.Close()

	certs := resp.TLS.PeerCertificates
	var crtcount int
	for _, cert := range certs {
		if cert.IsCA {
			crtcount++
			filename := fmt.Sprintf("%s.ca.%d.crt", hostURL.Hostname(), crtcount)
			fmt.Printf("  exporting CA cert to %s.\n", filename)
			f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("could not open %s for writing", filename)
			}
			defer f.Close()
			_, err = f.Write(cert.Raw)
			if err != nil {
				log.Fatal("Error writing certs to disk.")
			}
		}
	}

	fmt.Println("Done.")

}
