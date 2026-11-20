// This file is part of MinIO Console Server
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/console/pkg/certs"
	"github.com/minio/console/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests of this file change CONSOLE_OUTBOUND_TLS_VERIFY, GlobalRootCAs and
// the TLS configuration of GlobalTransport, so none of them runs in parallel.

// notSet stands for a CONSOLE_OUTBOUND_TLS_VERIFY that is not in the environment.
const notSet = "<not set>"

// setOutboundTLSVerify gives CONSOLE_OUTBOUND_TLS_VERIFY the value for the rest
// of the test, or takes the variable out of the environment for notSet.
func setOutboundTLSVerify(t *testing.T, value string) {
	t.Helper()
	if value != notSet {
		t.Setenv(ConsoleOutboundTLSVerify, value)
		return
	}
	// t.Setenv puts the variable back when the test ends.
	t.Setenv(ConsoleOutboundTLSVerify, "")
	require.NoError(t, os.Unsetenv(ConsoleOutboundTLSVerify))
}

// configureGlobalTransportTLS does for one test what the server command does
// at start: with the setting at value and rootCAs as the CA certificates that
// were loaded, it calls ConfigureGlobalTransportTLS. When the test ends,
// GlobalRootCAs and the TLS configuration of GlobalTransport are back as they
// were.
func configureGlobalTransportTLS(t *testing.T, value string, rootCAs *x509.CertPool) error {
	t.Helper()
	oldTLSConfig, oldRootCAs := GlobalTransport.TLSClientConfig, GlobalRootCAs
	t.Cleanup(func() {
		GlobalTransport.TLSClientConfig, GlobalRootCAs = oldTLSConfig, oldRootCAs
		GlobalTransport.CloseIdleConnections()
	})
	setOutboundTLSVerify(t, value)
	GlobalRootCAs = rootCAs
	return ConfigureGlobalTransportTLS()
}

// noContent answers every request with 204, a status that a log or audit
// webhook may answer with.
var noContent = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

// newTLSServer starts an HTTPS server on 127.0.0.1. Its certificate is the one
// of httptest, which names 127.0.0.1 and which no CA of the system has signed.
func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(noContent)
	t.Cleanup(srv.Close)
	return srv
}

// newTLSServerWith starts an HTTPS server on 127.0.0.1 with a self-signed
// certificate made for the test. Before change runs, the certificate names
// 127.0.0.1, the host of the server's URL, and is valid for an hour more.
func newTLSServerWith(t *testing.T, change func(certificate *x509.Certificate)) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "a certificate of api/tls_test.go"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	change(template)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(noContent)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newTLSServerNaming starts an HTTPS server on 127.0.0.1 whose certificate
// names dnsName and nothing else, so it does not name the host of the
// server's URL.
func newTLSServerNaming(t *testing.T, dnsName string) *httptest.Server {
	t.Helper()
	return newTLSServerWith(t, func(certificate *x509.Certificate) {
		certificate.IPAddresses = nil
		certificate.DNSNames = []string{dnsName}
	})
}

// newTLSServerExpired starts an HTTPS server on 127.0.0.1 whose certificate
// names the host of the server's URL and expired an hour ago.
func newTLSServerExpired(t *testing.T) *httptest.Server {
	t.Helper()
	return newTLSServerWith(t, func(certificate *x509.Certificate) {
		certificate.NotAfter = time.Now().Add(-time.Hour)
	})
}

// poolOf returns a pool that holds the given certificates and no other.
func poolOf(certificates ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

// outboundClients returns one client for each way in which the console gets
// to GlobalTransport.
func outboundClients() map[string]*http.Client {
	return map[string]*http.Client{
		// the login, the S3 client of minio-go, the download of a shared object
		"GetConsoleHTTPClient": GetConsoleHTTPClient(""),
		// the admin client, and the transport the logger is initialized with
		"PrepareSTSClientTransport": {Transport: PrepareSTSClientTransport("")},
		// the S3 client of mc, the OpenID end-session request
		"GlobalTransport": {Transport: GlobalTransport},
	}
}

// get sends one GET request. It reports whether the request went over a
// connection that an earlier request had left open.
func get(client *http.Client, url string) (reused bool, err error) {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return reused, err
	}
	return reused, resp.Body.Close()
}

// isUnknownAuthority reports whether err says that no accepted CA has signed
// the certificate.
func isUnknownAuthority(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthority)
}

// isHostnameError reports whether err says that the certificate does not name
// the host.
func isHostnameError(err error) bool {
	var hostname x509.HostnameError
	return errors.As(err, &hostname)
}

// isExpired reports whether err says that the certificate is outside the
// time it is valid for.
func isExpired(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}

func TestLookupOutboundTLSVerify(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    bool
		wantErr bool
	}{
		{name: "not set", value: notSet},
		{name: "empty", value: ""},
		{name: "white space only", value: "  "},
		{name: "off", value: "off"},
		{name: "off in upper case", value: "OFF"},
		{name: "on", value: "on", want: true},
		{name: "on in upper case", value: "ON", want: true},
		{name: "on in mixed case", value: "On", want: true},
		{name: "on with white space around it", value: " on ", want: true},
		{name: "true", value: "true", wantErr: true},
		{name: "1", value: "1", wantErr: true},
		{name: "yes", value: "yes", wantErr: true},
		{name: "enabled", value: "enabled", wantErr: true},
		{name: "false", value: "false", wantErr: true},
		{name: "0", value: "0", wantErr: true},
		{name: "a mistyped on", value: "onn", wantErr: true},
		// Values that begin with "env". The comment of lookupOutboundTLSVerify
		// says why they are cases of their own.
		{name: "env", value: "env", wantErr: true},
		{name: "a word that begins with env", value: "environment", wantErr: true},
		{name: "the address of a remote value", value: "env://user:key@127.0.0.1:1/on", wantErr: true},
		{name: "the address of a remote value over TLS", value: "env+tls://user:key@127.0.0.1:1/on", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOutboundTLSVerify(t, tt.value)

			verify, err := lookupOutboundTLSVerify()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ConsoleOutboundTLSVerify)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, verify, "lookupOutboundTLSVerify()")
			// Any certificate is accepted only for a value that means "off".
			assert.Equal(t, !tt.want && !tt.wantErr, outboundTLSSkipVerify(), "outboundTLSSkipVerify()")
		})
	}
}

// The error for a value that is not valid does not repeat the value: in the
// form that env.Get knows, the value can hold a user name and a key.
func TestLookupOutboundTLSVerifyKeepsTheValueOutOfTheError(t *testing.T) {
	setOutboundTLSVerify(t, "env://the-user:the-key@127.0.0.1:1/on")

	_, err := lookupOutboundTLSVerify()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "the-user")
	assert.NotContains(t, err.Error(), "the-key")

	err = ConfigureGlobalTransportTLS()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "the-user")
	assert.NotContains(t, err.Error(), "the-key")
}

func TestConfigureGlobalTransportTLS(t *testing.T) {
	// Its certificate names 127.0.0.1, the host of its URL.
	srv := newTLSServer(t)
	// Its certificate does not name 127.0.0.1, the host of its URL.
	otherName := newTLSServerNaming(t, "minio.example.test")
	// Its certificate names 127.0.0.1 and has expired.
	expired := newTLSServerExpired(t)

	tests := []struct {
		name    string
		value   string
		rootCAs *x509.CertPool
		url     string
		// refused is nil when the certificate has to be accepted. Otherwise
		// it says whether an error is the one the request has to fail with.
		refused func(error) bool
	}{
		{
			name:    "not set, no CA for the certificate",
			value:   notSet,
			rootCAs: poolOf(),
			url:     srv.URL,
		},
		{
			name:    "not set, no CA certificates loaded",
			value:   notSet,
			rootCAs: nil,
			url:     srv.URL,
		},
		{
			name:    "not set, the certificate does not name the host",
			value:   notSet,
			rootCAs: poolOf(),
			url:     otherName.URL,
		},
		{
			name:    "not set, the certificate has expired",
			value:   notSet,
			rootCAs: poolOf(),
			url:     expired.URL,
		},
		{
			name:    "off, no CA for the certificate",
			value:   "off",
			rootCAs: poolOf(),
			url:     srv.URL,
		},
		{
			name:    "on, no CA for the certificate",
			value:   "on",
			rootCAs: poolOf(),
			url:     srv.URL,
			refused: isUnknownAuthority,
		},
		{
			name:    "on, no CA certificates loaded",
			value:   "on",
			rootCAs: nil,
			url:     srv.URL,
			refused: isUnknownAuthority,
		},
		{
			name:    "on, the CA of another server loaded",
			value:   "on",
			rootCAs: poolOf(otherName.Certificate()),
			url:     srv.URL,
			refused: isUnknownAuthority,
		},
		{
			name:    "on, the CA of the certificate loaded",
			value:   "on",
			rootCAs: poolOf(srv.Certificate()),
			url:     srv.URL,
		},
		{
			name:    "on, the CA loaded, the certificate does not name the host",
			value:   "on",
			rootCAs: poolOf(otherName.Certificate()),
			url:     otherName.URL,
			refused: isHostnameError,
		},
		{
			name:    "on, the CA loaded, the certificate has expired",
			value:   "on",
			rootCAs: poolOf(expired.Certificate()),
			url:     expired.URL,
			refused: isExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, configureGlobalTransportTLS(t, tt.value, tt.rootCAs))

			for name, client := range outboundClients() {
				// Every client has to go through a TLS handshake of its own.
				GlobalTransport.CloseIdleConnections()
				_, err := get(client, tt.url)
				if tt.refused == nil {
					assert.NoError(t, err, name)
					continue
				}
				if assert.Error(t, err, name) {
					assert.Truef(t, tt.refused(err), "%s: the request failed with another error: %v", name, err)
				}
			}
		})
	}
}

// A value that is neither "on" nor "off" is an error, and the transport keeps
// the configuration it had.
func TestConfigureGlobalTransportTLSInvalidSetting(t *testing.T) {
	srv := newTLSServer(t)
	client := GetConsoleHTTPClient("")

	require.NoError(t, configureGlobalTransportTLS(t, "on", poolOf()))
	before := GlobalTransport.TLSClientConfig

	for _, value := range []string{"true", "environment"} {
		err := configureGlobalTransportTLS(t, value, poolOf(srv.Certificate()))
		require.Error(t, err, value)
		assert.Contains(t, err.Error(), ConsoleOutboundTLSVerify, value)
		assert.Same(t, before, GlobalTransport.TLSClientConfig, value)
	}

	_, err := get(client, srv.URL)
	assert.Truef(t, isUnknownAuthority(err), "the request did not fail on the certificate: %v", err)
}

// A connection that was opened before ConfigureGlobalTransportTLS ran is not
// used by a request that comes after it.
func TestConfigureGlobalTransportTLSClosesIdleConnections(t *testing.T) {
	srv := newTLSServer(t)
	client := GetConsoleHTTPClient("")

	require.NoError(t, configureGlobalTransportTLS(t, notSet, poolOf()))
	_, err := get(client, srv.URL)
	require.NoError(t, err)
	reused, err := get(client, srv.URL)
	require.NoError(t, err)
	require.True(t, reused, "the second request did not use the connection of the first, so this test shows nothing")

	require.NoError(t, configureGlobalTransportTLS(t, "on", poolOf()))
	reused, err = get(client, srv.URL)
	assert.False(t, reused, "the request used a connection from before the configuration")
	assert.Truef(t, isUnknownAuthority(err), "the request did not fail on the certificate: %v", err)
}

// ConfigureGlobalTransportTLS also works on a GlobalTransport that has no TLS
// configuration yet.
func TestConfigureGlobalTransportTLSWithoutTLSConfig(t *testing.T) {
	srv := newTLSServer(t)
	client := GetConsoleHTTPClient("")

	oldTLSConfig := GlobalTransport.TLSClientConfig
	t.Cleanup(func() { GlobalTransport.TLSClientConfig = oldTLSConfig })
	GlobalTransport.TLSClientConfig = nil

	require.NoError(t, configureGlobalTransportTLS(t, "on", poolOf()))
	assert.Equal(t, uint16(tls.VersionTLS12), GlobalTransport.TLSClientConfig.MinVersion)
	_, err := get(client, srv.URL)
	assert.Truef(t, isUnknownAuthority(err), "the request did not fail on the certificate: %v", err)

	GlobalTransport.TLSClientConfig = nil
	require.NoError(t, configureGlobalTransportTLS(t, "on", poolOf(srv.Certificate())))
	_, err = get(client, srv.URL)
	assert.NoError(t, err)
}

// The CA certificates that the server command loads at start are the ones
// that count: a certificate is accepted once its CA is a file of the CAs
// directory.
func TestConfigureGlobalTransportTLSWithCAsDirectory(t *testing.T) {
	srv := newTLSServer(t)
	client := GetConsoleHTTPClient("")

	// The directories, as loadAllCerts of cmd/console sets them for --certs-dir.
	certsDir := t.TempDir()
	caDir := filepath.Join(certsDir, certs.CertsCADir)
	require.NoError(t, os.Mkdir(caDir, 0o700))
	oldCertsDir, oldCertsCADir := certs.GlobalCertsDir, certs.GlobalCertsCADir
	t.Cleanup(func() { certs.GlobalCertsDir, certs.GlobalCertsCADir = oldCertsDir, oldCertsCADir })
	certs.GlobalCertsDir = &certs.ConfigDir{Path: certsDir}
	certs.GlobalCertsCADir = &certs.ConfigDir{Path: caDir}

	rootCAs, _, _, err := certs.GetAllCertificatesAndCAs()
	require.NoError(t, err)
	require.NoError(t, configureGlobalTransportTLS(t, "on", rootCAs))
	_, err = get(client, srv.URL)
	assert.Truef(t, isUnknownAuthority(err), "with an empty CAs directory the request did not fail on the certificate: %v", err)

	caFile := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(filepath.Join(caDir, "ca.crt"), caFile, 0o600))

	rootCAs, _, _, err = certs.GetAllCertificatesAndCAs()
	require.NoError(t, err)
	require.NoError(t, configureGlobalTransportTLS(t, "on", rootCAs))
	_, err = get(client, srv.URL)
	assert.NoError(t, err, "with the CA in the CAs directory")
}

// The log webhook and the audit webhook send their entries through a clone of
// GlobalTransport, which the logger takes when it is initialized. The server
// command initializes it after ConfigureGlobalTransportTLS, as this test does.
func TestConfigureGlobalTransportTLSForWebhooks(t *testing.T) {
	srv := newTLSServer(t)

	// The logger also contacts every webhook that the environment of the test
	// run enables. This test is about its own webhook only.
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(name, logger.EnvLoggerWebhookEnable) || strings.HasPrefix(name, logger.EnvAuditWebhookEnable) {
			t.Setenv(name, "")
		}
	}

	webhooks := []struct {
		name        string
		enableEnv   string
		endpointEnv string
	}{
		{
			name:        "log webhook",
			enableEnv:   logger.EnvLoggerWebhookEnable + "_TLSTEST",
			endpointEnv: logger.EnvLoggerWebhookEndpoint + "_TLSTEST",
		},
		{
			name:        "audit webhook",
			enableEnv:   logger.EnvAuditWebhookEnable + "_TLSTEST",
			endpointEnv: logger.EnvAuditWebhookEndpoint + "_TLSTEST",
		},
	}
	tests := []struct {
		name    string
		value   string
		rootCAs *x509.CertPool
		refused func(error) bool
	}{
		{
			name:    "not set, no CA for the certificate",
			value:   notSet,
			rootCAs: poolOf(),
		},
		{
			name:    "on, no CA for the certificate",
			value:   "on",
			rootCAs: poolOf(),
			refused: isUnknownAuthority,
		},
		{
			name:    "on, the CA of the certificate loaded",
			value:   "on",
			rootCAs: poolOf(srv.Certificate()),
		},
	}
	for _, webhook := range webhooks {
		for _, tt := range tests {
			t.Run(webhook.name+"/"+tt.name, func(t *testing.T) {
				t.Setenv(webhook.enableEnv, "on")
				t.Setenv(webhook.endpointEnv, srv.URL)
				// Take the webhook of this test out of the logger again.
				t.Cleanup(func() {
					assert.NoError(t, logger.UpdateSystemTargets(logger.NewConfig()))
					assert.NoError(t, logger.UpdateAuditWebhookTargets(logger.NewConfig()))
				})

				require.NoError(t, configureGlobalTransportTLS(t, tt.value, tt.rootCAs))
				transport := PrepareSTSClientTransport(LocalAddress).Transport.(*http.Transport)
				err := logger.InitializeLogger(context.Background(), transport)

				if tt.refused == nil {
					assert.NoError(t, err)
					return
				}
				if assert.Error(t, err) {
					assert.Truef(t, tt.refused(err), "the logger failed with another error: %v", err)
				}
			})
		}
	}
}
