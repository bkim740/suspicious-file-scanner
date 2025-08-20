# Suspicious File Scanner

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight malware triage tool written in **Go**.  
Detects abnormal entropy, computes **MD5/SHA1/SHA256** hashes, supports **JSON/CSV reports**, and integrates with **threat intelligence**.

---

## ✦ Features
- **Entropy Analysis** → flags files with abnormal randomness (packed/encrypted binaries).  
- **Hashing** → MD5, SHA-1, and SHA-256 for integrity checks and correlation.  
- **Structured Reports** → export to JSON or CSV for automation and analysis.  
- **Batch Scanning** → recursively scan a directory of files.  
- **VirusTotal (optional)** → lookup by hash when `VT_API_KEY` is set.  

---

## ⚙ Install & Build
```bash
git clone https://github.com/bkim740/suspicious-file-scanner.git
cd suspicious-file-scanner
go mod tidy
go build -o sfs

