package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Result struct {
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	MD5         string   `json:"md5"`
	SHA1        string   `json:"sha1"`
	SHA256      string   `json:"sha256"`
	Entropy     float64  `json:"entropy"`
	YARAMatches []string `json:"yara_matches,omitempty"`
	VTDetected  bool     `json:"vt_detected,omitempty"`
	VTLink      string   `json:"vt_link,omitempty"`
	ScannedAt   string   `json:"scanned_at"`
}

func main() {
	root := flag.String("path", ".", "File or directory to scan")
	jsonOut := flag.Bool("json", false, "Output JSON to stdout")
	csvOut := flag.Bool("csv", false, "Output CSV to stdout")
	useVT := flag.Bool("vt", false, "VirusTotal hash lookup (needs VT_API_KEY)")
	flag.Parse()

	var results []Result
	filepath.Walk(*root, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if info.IsDir() { return nil }
		r, err := scanFile(path, *useVT)
		if err == nil { results = append(results, r) }
		return nil
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	if *csvOut {
		w := csv.NewWriter(os.Stdout)
		defer w.Flush()
		w.Write([]string{"path","size","md5","sha1","sha256","entropy","yara_matches","vt_detected","vt_link","scanned_at"})
		for _, r := range results {
			w.Write([]string{r.Path, fmt.Sprint(r.Size), r.MD5, r.SHA1, r.SHA256, fmt.Sprintf("%.3f", r.Entropy),
				fmt.Sprint(r.YARAMatches), fmt.Sprint(r.VTDetected), r.VTLink, r.ScannedAt})
		}
		return
	}

	for _, r := range results {
		fmt.Printf("%s | size=%d | sha256=%s | entropy=%.3f | vt=%v\n",
			r.Path, r.Size, r.SHA256, r.Entropy, r.VTDetected)
	}
}

func scanFile(path string, vt bool) (Result, error) {
	b, err := os.ReadFile(path)
	if err != nil { return Result{}, err }

	md5h := md5.Sum(b)
	sha1h := sha1.Sum(b)
	sha256h := sha256.Sum256(b)

	res := Result{
		Path: path,
		Size: int64(len(b)),
		MD5: hex.EncodeToString(md5h[:]),
		SHA1: hex.EncodeToString(sha1h[:]),
		SHA256: hex.EncodeToString(sha256h[:]),
		Entropy: shannonEntropy(b),
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// TODO: integrate YARA via github.com/hillu/go-yara (optional)

	if vt {
		vtDetected, vtLink := vtQuery(res.SHA256)
		res.VTDetected = vtDetected
		res.VTLink = vtLink
	}

	return res, nil
}

func shannonEntropy(b []byte) float64 {
	var freq [256]int
	for _, v := range b { freq[v]++ }
	n := float64(len(b))
	var H float64
	for _, c := range freq {
		if c == 0 { continue }
		p := float64(c) / n
		H += -p * math.Log2(p)
	}
	return H
}

func vtQuery(sha256 string) (bool, string) {
	key := os.Getenv("VT_API_KEY")
	if key == "" { return false, "" }
	url := "https://www.virustotal.com/api/v3/files/" + sha256
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return false, "https://www.virustotal.com/gui/file/" + sha256
	}
	defer resp.Body.Close()
	return true, "https://www.virustotal.com/gui/file/" + sha256
}
