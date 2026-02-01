package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	"golang.org/x/net/html"
)

var (
	domain="example.com"

	customHeaders = map[string]string{
		"Accept": "*/*",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
	}

	virtusTotalKey = "<insert_key_here>"

	subdomains = map[string]string{}
)

func addToSubdomainsList(subdomain string) {
	subdomains[subdomain] = subdomain
}

func crtProcessResponse(doc *html.Node) {

	if doc.FirstChild != nil && doc.FirstChild.Type == html.TextNode {

		m := regexp.MustCompile(`[a-z0-9\-\.]+` + domain + ``)

		indexes := m.FindStringIndex(doc.FirstChild.Data)

		if len(indexes) > 0 {
			subdomain := string(doc.FirstChild.Data[indexes[0]:indexes[1]])

			addToSubdomainsList(subdomain)
		}
	}
}

func crtEnumerateResponse(doc *html.Node) {

	if doc.Type == html.ElementNode && doc.Data == "td" {
		crtProcessResponse(doc)
	}

	//Loop to resursivley traverse all elements
	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		crtEnumerateResponse(child)
	}
}

func crtQuery(input string) {

	url := "https://crt.sh/?q=" + input + "&exclude=expired&group=none"

	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns: 1000,
		MaxIdleConnsPerHost: 1000,
    }

	var netClient = &http.Client {
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error making request: ", err)
	}

	for name, value := range customHeaders {
		req.Header.Add(name,value)
	}

	res, err := netClient.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v", err)
	} else {

		doc, err := html.Parse(res.Body)
		if err != nil {
			log.Fatal("Error reading response body: ", err)
		}

		crtEnumerateResponse(doc)
	}
}

func virusTotalQuery(input string) {

	url := "https://www.virustotal.com/api/v3/domains/" + input + "/subdomains?limit=1000"
	
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns: 1000,
		MaxIdleConnsPerHost: 1000,
    }

	var netClient = &http.Client {
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error making request: ", err)
	}

	for name, value := range customHeaders {
		req.Header.Add(name,value)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Add("X-Apikey", virtusTotalKey)

	res, err := netClient.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v", err)
	} else {
		bytes, _ := io.ReadAll(res.Body)

		resBody := string(bytes)

		m := regexp.MustCompile(`\"id\"\s*\:\s*\"[a-z0-9\-\.]+\"`)

		indexes := m.FindAllStringIndex(resBody, -1)

		for _, indexPairs := range indexes {
			addToSubdomainsList(resBody[indexPairs[0] + 7:indexPairs[1] - 1])
		}
	}
}

func main() {
	crtQuery(domain)
	fmt.Println("CRT done")

	virusTotalQuery(domain)
	fmt.Println("Virus Total done")

	var f *os.File

	f, err := os.Create("output")
	if err != nil {
		log.Printf("Weird File Error: %s", err)
	}

	for subdomain, _ := range subdomains {
		f.WriteString(subdomain + "\n")
	}

	f.Close()
}
