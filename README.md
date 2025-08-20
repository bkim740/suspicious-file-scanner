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


## Usage

Scan a directory of files (example: `samples` folder included):

```bash
./sfs -path ./samples


# Append Usage + Example Output to README.md
cat >> README.md << 'EOF'

## Usage

Scan a directory of files (example: `samples` folder included):

```bash
./sfs -path ./samples


## Usage

Scan a directory of files (example: `samples` folder included):

```bash
./sfs -path ./samples
{
  "file": "samples/test.bin",
  "entropy": 7.92,
  "md5": "5d41402abc4b2a76b9719d911017c592",
  "sha1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "suspicious": true
}
