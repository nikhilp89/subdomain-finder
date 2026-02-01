# Subdomain Enumeration Tool

A lightweight subdomain enumeration tool written in Go that discovers subdomains for a target domain using multiple passive reconnaissance sources.

# Overview

This tool queries two popular certificate transparency and threat intelligence sources to discover subdomains:

crt.sh - Certificate Transparency logs
VirusTotal - Threat intelligence platform (requires API key)

# Prerequisites

Go 1.16 or higher
VirusTotal API key (free or premium)
Installation

Clone or download this repository

Install dependencies:

go get golang.org/x/net/html

Configure the tool by editing the following variables in main.go:
domain = "example.com"              // Your target domain
virtusTotalKey = "<insert_key_here>" // Your VirusTotal API key

# Usage

Basic Usage

go run main.go

Build and Run

# Build the binary
go build -o subdomain-enum main.go

# Run the binary
./subdomain-enum

Output

The tool will:

Query crt.sh for certificate transparency logs
Query VirusTotal API for known subdomains
Save all discovered subdomains to a file named output
Example output file:

mail.example.com
www.example.com
api.example.com
dev.example.com

# Configuration

Domain Target

Change the target domain in the domain variable:

domain = "yourdomain.com"

VirusTotal API Key

Get a free API key from VirusTotal and set it:

virtusTotalKey = "your_api_key_here"

Custom Headers

Modify the customHeaders map to change HTTP request headers:

customHeaders = map[string]string{
    "Accept": "*/*",
    "User-Agent": "Your custom user agent",
}

# How It Works

crt.sh Query:

Queries certificate transparency logs for the target domain
Parses HTML response to extract subdomain names from table data
Uses regex pattern matching to identify valid subdomains
VirusTotal Query:

Queries VirusTotal API v3 for known subdomains
Limits results to 1000 subdomains
Parses JSON response using regex to extract subdomain IDs
Deduplication:

Uses a map structure to automatically deduplicate findings
Ensures each subdomain is only listed once
Output:

Writes all unique subdomains to an output file
One subdomain per line
Code Structure

├── main.go
    ├── addToSubdomainsList()     // Adds subdomain to global map
    ├── crtProcessResponse()       // Processes individual HTML nodes
    ├── crtEnumerateResponse()     // Recursively traverses HTML DOM
    ├── crtQuery()                 // Queries crt.sh
    ├── virusTotalQuery()          // Queries VirusTotal API
    └── main()                     // Orchestrates execution

