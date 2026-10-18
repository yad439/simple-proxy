package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	netProxy "golang.org/x/net/proxy"
)

func NewProxyHandler(timeoutSeconds int) *ProxyHandler {
	return &ProxyHandler{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

type ProxyHandler struct {
	Timeout       time.Duration
	Username      *string
	Password      *string
	LogAuth       bool
	LogHeaders    bool
	Socks5Forward *Socks5Forward
	HTTPForward   *HTTPForward

	transportOnce sync.Once
	transport     http.RoundTripper
}

type HTTPForward struct {
	Address  string
	Username *string
	Password *string
}

func (f *HTTPForward) authHeader() string {
	if f.Username == nil || f.Password == nil {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(*f.Username+":"+*f.Password))
}

func (f *HTTPForward) dial(host string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", f.Address, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: host},
		Host:   host,
		Header: http.Header{},
	}
	if auth := f.authHeader(); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy refused CONNECT: %s", resp.Status)
	}
	conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (f *HTTPForward) transport() *http.Transport {
	u := &url.URL{Scheme: "http", Host: f.Address}
	t := &http.Transport{Proxy: http.ProxyURL(u)}
	if auth := f.authHeader(); auth != "" {
		t.ProxyConnectHeader = http.Header{"Proxy-Authorization": {auth}}
	}
	return t
}

type Socks5Forward struct {
	Address  string
	Username *string
	Password *string
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	glog.V(1).Infof("Serving '%s' request from '%s' to '%s'\n", r.Method, r.RemoteAddr, r.Host)
	if p.LogHeaders {
		for name, values := range r.Header {
			for i, value := range values {
				glog.V(1).Infof("'%s': [%d] %s", name, i, value)
			}
		}
	}
	if p.Username != nil && p.Password != nil {
		username, password, ok := proxyBasicAuth(r)
		if !ok || username != *p.Username || password != *p.Password {
			if p.LogAuth {
				glog.Errorf("Unauthorized, username: %s, password: %s\n", username, password)
			} else {
				glog.Errorln("Unauthorized")
			}
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}
	}
	if r.Method == http.MethodConnect {
		handleTunneling(w, r, p.Timeout, p.Socks5Forward, p.HTTPForward)
	} else {
		handleHTTP(w, r, p.httpTransport())
	}
}

func (p *ProxyHandler) httpTransport() http.RoundTripper {
	p.transportOnce.Do(func() {
		if p.HTTPForward != nil {
			p.transport = p.HTTPForward.transport()
		} else {
			p.transport = http.DefaultTransport
		}
	})
	return p.transport
}

func handleTunneling(w http.ResponseWriter, r *http.Request, timeout time.Duration, socks5Forward *Socks5Forward, httpForward *HTTPForward) {
	var destConn net.Conn
	var err error

	if httpForward != nil {
		destConn, err = httpForward.dial(r.Host, timeout)
	} else if socks5Forward == nil {
		destConn, err = net.DialTimeout("tcp", r.Host, timeout)
	} else {
		var socks5Auth *netProxy.Auth
		if socks5Forward.Username != nil && socks5Forward.Password != nil {
			socks5Auth = &netProxy.Auth{
				User:     *socks5Forward.Username,
				Password: *socks5Forward.Password,
			}
		}

		var socks5Dialer netProxy.Dialer
		socks5Dialer, err = netProxy.SOCKS5("tcp", socks5Forward.Address, socks5Auth, &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		})

		if err != nil {
			glog.Errorf("Failed to dial socks5 proxy %s, %s\n", socks5Forward.Address, err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		destConn, err = socks5Dialer.Dial("tcp", r.Host)
	}

	if err != nil {
		glog.Errorf("Failed to dial host, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		glog.Errorln("Attempted to hijack connection that does not support it")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		glog.Errorf("Failed to hijack connection, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request, transport http.RoundTripper) {
	resp, err := transport.RoundTrip(req)
	if err != nil {
		glog.Errorf("Failed to proxy request, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func proxyBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	return parseBasicAuth(auth)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !equalFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
