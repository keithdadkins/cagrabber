package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	// parse flags
	// host := flag.String("host", "", "Host address to grab the certs from. Hostname or full `URL`")
	outfile := flag.Bool("w", false, "Write certs to a file instead of stdout.")
	flag.Parse()

	// The only positional argument should be a url to a host.
	if flag.NArg() != 1 {
		flag.Usage()
		fmt.Println("Too many args passed in.")
		os.Exit(1)
	}
	host := fmt.Sprint(flag.Arg(0))

	// handle proto
	if !strings.HasPrefix(host, "https://") {
		if strings.HasPrefix(host, "http://") {
			fmt.Println("Cannot use http protocol to retrieve certs. Did you mean to use https?")
			os.Exit(1)
		}
		host = "https://" + host
	}

	// Parse the url and check for errors
	hostURL, err := url.Parse(host)
	if err != nil {
		fmt.Println("Error parsing url")
		panic(err)
	}

	// Handle port (hostURL.Port() returns a string)
	var port int
	switch hostURL.Port() {
	case "":
		port = 443
	default:
		port, err = strconv.Atoi(hostURL.Port())
		if err != nil {
			panic("Could not parse port. Please check the url.")
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
	if *outfile {
		fmt.Printf("Grepping %s for CA certificates..\n", hostURL.Hostname())
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Get(hosturl)
	if err != nil {
		fmt.Println("Error connecting to host.")
		fmt.Print(err)
		os.Exit(1)
	}

	// parse the certs
	certs := resp.TLS.PeerCertificates
	var crtcount int
	for _, cert := range certs {
		if cert.IsCA {
			crtcount++
			if *outfile {
				// write each cert to a file.
				// TODO: see if these can be written to one file.
				filename := fmt.Sprintf("%s.ca.%d.crt", hostURL.Hostname(), crtcount)
				fmt.Printf("  exporting CA cert to %s.\n", filename)
				f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Printf("could not open %s for writing", filename)
					os.Exit(1)
				}
				defer f.Close()
				_, err = f.Write(cert.Raw)
				if err != nil {
					panic("Error writing certs to disk.")
				}
			} else {
				// write to stdout
				_, err := os.Stdout.Write(cert.Raw)
				if err != nil {
					panic("Could not write to stdout")
				}
			}
		}
	}
	if *outfile {
		fmt.Println("Done.")
	}
}
