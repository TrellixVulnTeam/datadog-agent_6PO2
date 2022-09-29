// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf || (windows && npm)
// +build linux_bpf windows,npm

package tracer

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/http"
	"github.com/DataDog/datadog-agent/pkg/network/http/testutil"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/rand"
	"net"
	nethttp "net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	disableTLSVerification = sync.Once{}
)

func writeTempFile(pattern string, content string) (*os.File, error) {
	f, err := ioutil.TempFile("", pattern)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return nil, err
	}

	return f, nil
}

func rawConnect(ctx context.Context, t *testing.T, host string, port string) {
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("failed connecting to port %s:%s", host, port)
		default:
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
			if err != nil {
				continue
			}
			if conn != nil {
				conn.Close()
				return
			}
		}
	}

}

const pythonSSLServerFormat = `import http.server, ssl

class RequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    daemon_threads = True

    def do_GET(self):
        status_code = int(self.path.split("/")[1])
        self.send_response(status_code)
        self.end_headers()

server_address = ('127.0.0.1', 8001)
httpd = http.server.HTTPServer(server_address, RequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='%s',
                               keyfile='%s',
                               ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()
`

func TestOpenSSLVersions_python_matrix(t *testing.T) {
	if !httpSupported(t) {
		t.Skip("HTTPS feature not available on pre 4.14.0 kernels")
	}

	disableTLSVerification.Do(func() {
		nethttp.DefaultTransport.(*nethttp.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	})
	curDir, _ := testutil.CurDir()
	crtPath := filepath.Join(curDir, "testdata/cert.pem.0")
	keyPath := filepath.Join(curDir, "testdata/server.key")
	pythonSSLServer := fmt.Sprintf(pythonSSLServerFormat, crtPath, keyPath)
	scriptFile, err := writeTempFile("python_openssl_script", pythonSSLServer)
	require.NoError(t, err)
	defer scriptFile.Close()

	cmd := exec.Command("python3", scriptFile.Name())
	go func() {
		err := cmd.Start()
		if err != nil {
			fmt.Println(err)
		}
	}()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	cfg := config.New()
	cfg.EnableHTTPSMonitoring = true
	cfg.EnableHTTPMonitoring = true
	cfg.BPFDebug = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	err = tr.RegisterClient("1")
	require.NoError(t, err)
	defer tr.Stop()

	// Waiting for the server to be ready
	portCtx, cancelPortCtx := context.WithDeadline(context.Background(), time.Now().Add(time.Second*5))
	rawConnect(portCtx, t, "127.0.0.1", "8001")
	cancelPortCtx()

	requestFn := simpleGetRequestsGenerator(t, "127.0.0.1:8001")
	var requests []*nethttp.Request
	for i := 0; i < 100; i++ {
		requests = append(requests, requestFn())
	}

	assertAllRequestsExists(t, tr, requests)
}

var (
	statusCodes = []int{nethttp.StatusOK, nethttp.StatusMultipleChoices, nethttp.StatusBadRequest, nethttp.StatusInternalServerError}
)

func simpleGetRequestsGenerator(t *testing.T, targetAddr string) func() *nethttp.Request {
	var (
		random = rand.New(rand.NewSource(time.Now().Unix()))
		idx    = 0
		client = new(nethttp.Client)
	)

	return func() *nethttp.Request {
		idx++
		status := statusCodes[random.Intn(len(statusCodes))]
		req, err := nethttp.NewRequest(nethttp.MethodGet, fmt.Sprintf("https://%s/%d/request-%d", targetAddr, status, idx), nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode)
		resp.Body.Close()
		return req
	}
}

func assertAllRequestsExists(t *testing.T, tracer *Tracer, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))
	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		conns, err := tracer.GetActiveConnections("1")
		require.NoError(t, err)

		if len(conns.HTTP) == 0 {
			continue
		}
		for reqIndex, req := range requests {
			requestsExist[reqIndex] = requestsExist[reqIndex] || isRequestIncluded(conns.HTTP, req)
		}
	}

	for reqIndex, exists := range requestsExist {
		require.Truef(t, exists, "request %d was not found (req %v)", reqIndex, requests[reqIndex])
	}
}

func isRequestIncluded(allStats map[http.Key]*http.RequestStats, req *nethttp.Request) bool {
	expectedStatus := testutil.StatusFromPath(req.URL.Path)
	for key, stats := range allStats {
		if key.Path.Content == req.URL.Path && stats.HasStats(expectedStatus) {
			return true
		}
	}

	return false
}
