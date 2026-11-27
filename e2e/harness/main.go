// Command e2e-harness runs a real eap-enroll server against a fake OpenBao
// with a throwaway PKI, for the app's end-to-end tests. See ../README.md.
//
// It writes the PKI and the server configuration to -dir, starts
// "eap-enroll serve", and answers on a plain-HTTP control address on
// 127.0.0.1 (printed on standard output and written to -dir/control).
//
// Clients reach the server through a TCP proxy that connects from a new
// 127.x.y.z source address for every connection, so the server's per-address
// rate limits don't slow the tests down.
//
// With -attestation-roots the server requires Android hardware key
// attestation for device credentials; only a real phone can pass that. The
// harness then also serves the server's attestation revocation list: one
// made-up entry, so no real attestation key counts as revoked.
//
// Control requests:
//
//	POST /code?user=U&label=L   new one-time code; the body is the setup URI
//	POST /disable?device=ID     eap-enroll disable ID
//	POST /group?user=U&group=G  changes the user's group in the fake OpenBao
//	GET  /revoked               serials revoked in OpenBao, JSON {mount: [serial]}
//	GET  /devices               eap-enroll devices
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func newKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	return must(ecdsa.GenerateKey(curve, rand.Reader))
}

func issue(parent *ca, tmpl *x509.Certificate, pub crypto.PublicKey, selfKey crypto.Signer) *x509.Certificate {
	tmpl.SerialNumber = must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159)))
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	signerCert, signerKey := tmpl, selfKey
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey))
	return must(x509.ParseCertificate(der))
}

func newCA(parent *ca, name string) *ca {
	key := newKey(elliptic.P384())
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	return &ca{cert: issue(parent, tmpl, key.Public(), key), key: key}
}

func pemCert(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

func write(dir, name, content string) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		log.Fatal(err)
	}
	return p
}

// stringList is a flag that can be given more than once.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

func freePort() int {
	l := must(net.Listen("tcp", "127.0.0.1:0"))
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// fakeBao implements the OpenBao calls eap-enroll makes.
type fakeBao struct {
	root    *ca
	cas     map[string]*ca
	mu      sync.Mutex
	groups  map[string]any
	revoked map[string][]string
}

const (
	roleID   = "e2e-role-id"
	secretID = "e2e-secret-id"
	token    = "e2e-token"
)

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	var body map[string]any
	if r.Method == http.MethodPost {
		// revoke-self has no body.
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			reply(w, 400, map[string]any{"errors": []string{"bad json"}})
			return
		}
	}
	if path == "auth/approle/login" {
		if body["role_id"] != roleID || body["secret_id"] != secretID {
			reply(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": 3600}})
		return
	}
	if r.Header.Get("X-Vault-Token") != token {
		reply(w, 403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	switch {
	case r.Method == http.MethodGet && path == "kv/data/apps/freeradius/user-groups":
		reply(w, 200, map[string]any{"data": map[string]any{"data": f.groups}})
	case r.Method == http.MethodPost && strings.Contains(path, "/sign/"):
		f.sign(w, strings.SplitN(path, "/", 2)[0], body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/revoke"):
		mount := strings.TrimSuffix(path, "/revoke")
		f.revoked[mount] = append(f.revoked[mount], body["serial_number"].(string))
		reply(w, 200, map[string]any{"data": map[string]any{"revocation_time": time.Now().Unix()}})
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/crl/rotate"):
		reply(w, 200, map[string]any{"data": map[string]any{"success": true}})
	case r.Method == http.MethodPost && path == "auth/token/revoke-self":
		w.WriteHeader(http.StatusNoContent)
	default:
		reply(w, 404, map[string]any{"errors": []string{"no handler for " + path}})
	}
}

func (f *fakeBao) sign(w http.ResponseWriter, mount string, body map[string]any) {
	issuer := f.cas[mount]
	if issuer == nil {
		reply(w, 500, map[string]any{"errors": []string{"unknown mount"}})
		return
	}
	block, _ := pem.Decode([]byte(body["csr"].(string)))
	if block == nil {
		reply(w, 400, map[string]any{"errors": []string{"bad csr"}})
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		reply(w, 400, map[string]any{"errors": []string{"bad csr"}})
		return
	}
	ttl, err := time.ParseDuration(body["ttl"].(string))
	if err != nil {
		reply(w, 400, map[string]any{"errors": []string{"bad ttl"}})
		return
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: body["common_name"].(string)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		NotAfter:    time.Now().Add(ttl),
	}
	if u, ok := body["uri_sans"].(string); ok && u != "" {
		tmpl.URIs = []*url.URL{must(url.Parse(u))}
	}
	cert := issue(issuer, tmpl, csr.PublicKey, nil)
	var parts []string
	for _, b := range cert.SerialNumber.Bytes() {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	reply(w, 200, map[string]any{"data": map[string]any{
		"certificate":   pemCert(cert),
		"issuing_ca":    pemCert(issuer.cert),
		"ca_chain":      []string{pemCert(issuer.cert), pemCert(f.root.cert)},
		"serial_number": strings.Join(parts, ":"),
	}})
}

func main() {
	dir := flag.String("dir", "", "empty working directory")
	bin := flag.String("eap-enroll", "", "eap-enroll binary")
	publicPort := flag.Int("public-port", 0, "port on 127.0.0.1 for clients (default: any free port)")
	deviceTTL := flag.String("device-ttl", "8760h", "device credential lifetime (at least 1h; renewal is due at 2/3)")
	wifiTTL := flag.String("wifi-ttl", "1440h", "Wi-Fi certificate lifetime (at least 1h; renewal is due at 2/3)")
	attestationRoots := flag.String("attestation-roots", "", "require Android key attestation, trusting the roots in this PEM file (eap-enroll-server's deploy/attestation-roots.pem)")
	appPackage := flag.String("app-package", "eu.appwerf.eapenroll", "with -attestation-roots: the app's package name the attestation must name")
	var appSigningCerts stringList
	flag.Var(&appSigningCerts, "app-signing-cert", "with -attestation-roots: SHA-256 of the app's signing certificate in hex, colons allowed (repeatable; required)")
	flag.Parse()
	if *dir == "" || *bin == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *attestationRoots != "" && len(appSigningCerts) == 0 {
		fmt.Fprintln(os.Stderr, "-attestation-roots needs -app-signing-cert (see ../README.md)")
		os.Exit(2)
	}
	d := must(filepath.Abs(*dir))
	must(0, os.MkdirAll(d, 0o700))

	root := newCA(nil, "E2E Root")
	wifiCA := newCA(root, "E2E Wi-Fi CA")
	deviceCA := newCA(root, "E2E Device CA")
	setupCA := newCA(nil, "E2E TLS CA")
	serverKey := newKey(elliptic.P256())
	serverCert := issue(setupCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature, NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}, serverKey.Public(), nil)
	serverKeyDER := must(x509.MarshalPKCS8PrivateKey(serverKey))

	bao := &fakeBao{
		root: root, cas: map[string]*ca{"pki-radius": wifiCA, "pki-enroll": deviceCA},
		groups:  map[string]any{"alice": "staff", "bob": "disabled"},
		revoked: map[string][]string{},
	}
	baoServer := &http.Server{Handler: bao}
	baoListener := must(net.Listen("tcp", "127.0.0.1:0"))
	baoKey := newKey(elliptic.P256())
	baoCert := issue(setupCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "openbao"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature, NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}, baoKey.Public(), nil)
	baoServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{baoCert.Raw}, PrivateKey: baoKey}}}
	go func() { log.Fatal(baoServer.ServeTLS(baoListener, "", "")) }()
	// Trust anchors for the server's own HTTPS clients: the attestation
	// status list is served under setupCA (eap-enroll reaches OpenBao
	// through openbao.ca_file).
	serverEnv := append(os.Environ(), "SSL_CERT_FILE="+write(d, "server-roots.pem", pemCert(setupCA.cert)))

	port := freePort()
	proxyListener := must(net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *publicPort)))
	go proxy(proxyListener, fmt.Sprintf("127.0.0.1:%d", port))
	*publicPort = proxyListener.Addr().(*net.TCPAddr).Port
	cfg := map[string]any{
		"listen":              fmt.Sprintf("127.0.0.1:%d", port),
		"public_url":          fmt.Sprintf("https://127.0.0.1:%d", *publicPort),
		"tls_cert_file":       write(d, "tls.pem", pemCert(serverCert, setupCA.cert)),
		"tls_key_file":        write(d, "tls.key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))),
		"setup_ca_file":       write(d, "setup-ca.pem", pemCert(setupCA.cert)),
		"device_ca_file":      write(d, "device-ca.pem", pemCert(deviceCA.cert)),
		"wifi_cacerts_file":   write(d, "wifi-cacerts.pem", pemCert(wifiCA.cert, root.cert)),
		"device_cacerts_file": write(d, "device-cacerts.pem", pemCert(deviceCA.cert, root.cert)),
		"database":            filepath.Join(d, "enroll.db"),
		"wifi_ttl":            *wifiTTL,
		"device_ttl":          *deviceTTL,
		"wifi_profile": map[string]any{
			"ssid":           "Example Net ",
			"server_domain":  "radius.example.org",
			"server_ca_file": write(d, "radius-ca.pem", pemCert(root.cert)),
		},
		"openbao": map[string]any{
			"address":        "https://" + baoListener.Addr().String(),
			"ca_file":        write(d, "bao-ca.pem", pemCert(setupCA.cert)),
			"role_id_file":   write(d, "role-id", roleID+"\n"),
			"secret_id_file": write(d, "secret-id", secretID+"\n"),
		},
	}
	if *attestationRoots != "" {
		var certs []string
		for _, c := range appSigningCerts {
			certs = append(certs, strings.ReplaceAll(c, ":", ""))
		}
		cfg["key_attestation"] = map[string]any{
			"roots_file":        must(filepath.Abs(*attestationRoots)),
			"status_url":        serveStatusList(setupCA),
			"app_package":       *appPackage,
			"app_signing_certs": certs,
		}
	}
	config := write(d, "config.json", string(must(json.MarshalIndent(cfg, "", "  "))))

	serverLog := must(os.Create(filepath.Join(d, "server.log")))
	server := exec.Command(*bin, "serve", "-config", config)
	server.Stdout, server.Stderr = serverLog, serverLog
	server.Env = serverEnv
	must(0, server.Start())
	exited := make(chan error, 1)
	go func() { exited <- server.Wait() }()
	// On the way out, let the server finish (it revokes its OpenBao token
	// at exit) before the fake OpenBao goes away with this process.
	defer func() {
		server.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			server.Process.Kill()
		}
	}()
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			break
		}
		if i > 100 {
			log.Fatal("eap-enroll serve didn't start; see server.log")
		}
		select {
		case err := <-exited:
			log.Fatalf("eap-enroll serve exited: %v; see server.log", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	run := func(w http.ResponseWriter, args ...string) {
		var out, errOut bytes.Buffer
		cmd := exec.Command(*bin, append([]string{args[0], "-config", config}, args[1:]...)...)
		cmd.Stdout, cmd.Stderr = &out, &errOut
		cmd.Env = serverEnv
		if err := cmd.Run(); err != nil {
			http.Error(w, fmt.Sprintf("%v: %s", err, errOut.String()), 500)
			return
		}
		w.Write(out.Bytes())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /code", func(w http.ResponseWriter, r *http.Request) {
		run(w, "code", "-user", r.URL.Query().Get("user"), "-label", r.URL.Query().Get("label"))
	})
	mux.HandleFunc("POST /disable", func(w http.ResponseWriter, r *http.Request) {
		run(w, "disable", r.URL.Query().Get("device"))
	})
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) { run(w, "devices") })
	mux.HandleFunc("POST /group", func(w http.ResponseWriter, r *http.Request) {
		bao.mu.Lock()
		bao.groups[r.URL.Query().Get("user")] = r.URL.Query().Get("group")
		bao.mu.Unlock()
	})
	mux.HandleFunc("GET /revoked", func(w http.ResponseWriter, r *http.Request) {
		bao.mu.Lock()
		defer bao.mu.Unlock()
		reply(w, 200, bao.revoked)
	})
	control := must(net.Listen("tcp", "127.0.0.1:0"))
	go func() { log.Fatal(http.Serve(control, mux)) }()

	sum := sha256.Sum256(setupCA.cert.Raw)
	controlURL := "http://" + control.Addr().String()
	write(d, "control", controlURL+"\n")
	fmt.Printf("control %s\nserver https://127.0.0.1:%d\nsetup CA %s\n", controlURL, *publicPort, hex.EncodeToString(sum[:]))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
	case err := <-exited:
		log.Fatalf("eap-enroll serve exited: %v; see server.log", err)
	}
}

// serveStatusList serves an attestation revocation list in the format of
// Google's (https://android.googleapis.com/attestation/status) over HTTPS
// with a certificate from tlsCA, and returns its URL. The server refuses
// an empty list, so it has one entry with a serial no attestation
// certificate is expected to have.
func serveStatusList(tlsCA *ca) string {
	key := newKey(elliptic.P256())
	cert := issue(tlsCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "attestation status"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature, NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}, key.Public(), nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"entries": map[string]any{
			"e2e0000000000000000000000000000000000000": map[string]any{"status": "REVOKED", "reason": "KEY_COMPROMISE"},
		}})
	})
	server := &http.Server{Handler: mux, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
	}}
	l := must(net.Listen("tcp", "127.0.0.1:0"))
	go func() { log.Fatal(server.ServeTLS(l, "", "")) }()
	return "https://" + l.Addr().String() + "/status"
}

// proxy forwards connections to target, each from its own loopback address.
func proxy(l net.Listener, target string) {
	var n uint32
	for {
		in, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		n++
		local := &net.TCPAddr{IP: net.IPv4(127, byte(1+n/62500%250), byte(n/250%250), byte(2+n%250))}
		go func() {
			defer in.Close()
			out, err := (&net.Dialer{LocalAddr: local}).Dial("tcp", target)
			if err != nil {
				log.Printf("proxy: %v", err)
				return
			}
			defer out.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(out, in); out.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(in, out); in.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}
