// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
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
	"crypto/tls"
	"net/http"
)

type ConsoleTransport struct {
	Transport http.RoundTripper
	ClientIP  string
}

func (t *ConsoleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ClientIP != "" {
		// Do not set an empty x-forwarded-for
		req.Header.Add(xForwardedFor, t.ClientIP)
	}
	return t.Transport.RoundTrip(req)
}

// PrepareSTSClientTransport :
func PrepareSTSClientTransport(clientIP string) *ConsoleTransport {
	return &ConsoleTransport{
		Transport: GlobalTransport,
		ClientIP:  clientIP,
	}
}

// PrepareConsoleHTTPClient returns an http.Client that sends its requests through GlobalTransport,
// as *credentials.STSAssumeRole needs it. Whether the certificate of the server is verified, and
// with which CA certificates, is the configuration of GlobalTransport: see ConfigureGlobalTransportTLS.
func PrepareConsoleHTTPClient(clientIP string) *http.Client {
	// Return http client with default configuration
	return &http.Client{
		Transport: PrepareSTSClientTransport(clientIP),
	}
}

// ConfigureGlobalTransportTLS puts CONSOLE_OUTBOUND_TLS_VERIFY and the CA
// certificates of GlobalRootCAs on GlobalTransport.
//
// With the setting off, which is the default, GlobalTransport accepts any
// certificate and the CA certificates play no part. With the setting on,
// GlobalTransport verifies the certificate of the server against the CA
// certificates of GlobalRootCAs; a nil GlobalRootCAs stands for the CA
// certificates of the system.
//
// GlobalTransport is built before GlobalRootCAs is loaded, so the code that
// loads the CA certificates calls this afterwards, and before anything uses
// or clones GlobalTransport: a clone keeps the TLS configuration it was taken
// with.
//
// When lookupOutboundTLSVerify refuses the value of the setting,
// ConfigureGlobalTransportTLS returns its error and changes nothing.
func ConfigureGlobalTransportTLS() error {
	verify, err := lookupOutboundTLSVerify()
	if err != nil {
		return err
	}
	// A tls.Config must not be modified after a connection has used it, so
	// the transport gets a copy with the two values set.
	tlsConfig := GlobalTransport.TLSClientConfig.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsConfig.InsecureSkipVerify = !verify
	tlsConfig.RootCAs = GlobalRootCAs
	GlobalTransport.TLSClientConfig = tlsConfig
	// The idle connections were opened with the earlier configuration. They
	// are closed, so that no later request goes over one of them.
	GlobalTransport.CloseIdleConnections()
	return nil
}
