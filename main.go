package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Config — loaded from Docker secrets (_FILE variants) or plain env vars
// ---------------------------------------------------------------------------

var (
	vmanageHost string
	vmanageUser string
	vmanagePass string
	proxyToken  string
)

func readSecret(name string) (string, error) {
	if fp := os.Getenv(name + "_FILE"); fp != "" {
		data, err := os.ReadFile(fp)
		if err != nil {
			return "", fmt.Errorf("reading secret file for %s: %w", name, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("required env var %s (or %s_FILE) is not set", name, name)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

var sess struct {
	mu         sync.Mutex
	jsessionid string
	xsrfToken  string
}

// authenticate performs the two-step vManage login and stores the resulting
// tokens. Caller must hold sess.mu.
func authenticate() error {
	log.Printf("Authenticating to vManage at %s", vmanageHost)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("creating cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar}

	// Step 1: form-based login
	form := url.Values{"j_username": {vmanageUser}, "j_password": {vmanagePass}}
	resp, err := client.PostForm(vmanageHost+"/j_security_check", form)
	if err != nil {
		return fmt.Errorf("auth POST: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("auth POST returned HTTP %d", resp.StatusCode)
	}

	// Extract JSESSIONID from the cookie jar (populated through redirects)
	u, _ := url.Parse(vmanageHost)
	var jsessionid string
	for _, c := range jar.Cookies(u) {
		if c.Name == "JSESSIONID" {
			jsessionid = c.Value
			break
		}
	}
	if jsessionid == "" {
		return fmt.Errorf("no JSESSIONID in response — check credentials or vManage URL")
	}

	// Step 2: fetch XSRF token
	req, err := http.NewRequest(http.MethodGet, vmanageHost+"/dataservice/client/token", nil)
	if err != nil {
		return fmt.Errorf("building token request: %w", err)
	}
	req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: jsessionid})

	tokenResp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token GET: %w", err)
	}
	tokenBody, err := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	if err != nil {
		return fmt.Errorf("reading token response: %w", err)
	}
	if tokenResp.StatusCode >= 400 {
		return fmt.Errorf("token GET returned HTTP %d", tokenResp.StatusCode)
	}

	sess.jsessionid = jsessionid
	sess.xsrfToken = strings.TrimSpace(string(tokenBody))
	log.Println("Authentication successful")
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Read body once up-front so retries can replay it.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, `{"error":"failed to read request body"}`)
		return
	}

	doRequest := func() (*http.Response, error) {
		sess.mu.Lock()
		jsessionid := sess.jsessionid
		xsrfToken := sess.xsrfToken
		sess.mu.Unlock()

		target := vmanageHost + "/dataservice" + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("building upstream request: %w", err)
		}
		req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: jsessionid})
		req.Header.Set("X-XSRF-TOKEN", xsrfToken)
		return http.DefaultClient.Do(req)
	}

	// Ensure we have a valid session before the first request.
	sess.mu.Lock()
	if sess.jsessionid == "" {
		if err := authenticate(); err != nil {
			sess.mu.Unlock()
			log.Printf("Authentication error: %v", err)
			writeJSON(w, http.StatusBadGateway, `{"error":"upstream authentication failed"}`)
			return
		}
	}
	sess.mu.Unlock()

	upstream, err := doRequest()
	if err != nil {
		log.Printf("Upstream request error: %v", err)
		writeJSON(w, http.StatusBadGateway, `{"error":"upstream request failed"}`)
		return
	}

	// Session expired — re-authenticate once and retry.
	if upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden {
		io.Copy(io.Discard, upstream.Body) //nolint:errcheck
		upstream.Body.Close()

		log.Println("Session expired, re-authenticating…")
		sess.mu.Lock()
		if err := authenticate(); err != nil {
			sess.mu.Unlock()
			log.Printf("Re-authentication error: %v", err)
			writeJSON(w, http.StatusBadGateway, `{"error":"re-authentication failed"}`)
			return
		}
		sess.mu.Unlock()

		upstream, err = doRequest()
		if err != nil {
			log.Printf("Upstream request error after re-auth: %v", err)
			writeJSON(w, http.StatusBadGateway, `{"error":"upstream request failed"}`)
			return
		}
	}
	defer upstream.Body.Close()

	ct := upstream.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(upstream.StatusCode)
	io.Copy(w, upstream.Body) //nolint:errcheck
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	var err error
	for _, s := range []struct {
		dest *string
		name string
	}{
		{&vmanageHost, "VMANAGE_HOST"},
		{&vmanageUser, "VMANAGE_USER"},
		{&vmanagePass, "VMANAGE_PASS"},
		{&proxyToken, "PROXY_BEARER_TOKEN"},
	} {
		*s.dest, err = readSecret(s.name)
		if err != nil {
			log.Fatalf("Config: %v", err)
		}
	}

	mux := http.NewServeMux()

	// Health check — no auth required for Docker/k8s probes.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"status":"ok"}`)
	})

	// All other paths require a valid Bearer token, then proxy to vManage.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+proxyToken {
			log.Printf("Unauthorized request from %s", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, `{"error":"Unauthorized"}`)
			return
		}
		proxyHandler(w, r)
	})

	log.Println("Listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server: %v", err)
	}
}
