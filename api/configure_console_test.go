// This file is part of MinIO Console Server
// Copyright (c) 2022 MinIO, Inc.
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
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-openapi/loads"
	"github.com/minio/console/api/operations"
	"github.com/minio/console/pkg/auth"
	"github.com/minio/console/pkg/logger"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
)

func Test_parseSubPath(t *testing.T) {
	type args struct {
		v string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Empty",
			args: args{
				v: "",
			},
			want: "/",
		},
		{
			name: "Slash",
			args: args{
				v: "/",
			},
			want: "/",
		},
		{
			name: "Double Slash",
			args: args{
				v: "//",
			},
			want: "/",
		},
		{
			name: "No slashes",
			args: args{
				v: "route",
			},
			want: "/route/",
		},
		{
			name: "No trailing slashes",
			args: args{
				v: "/route",
			},
			want: "/route/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			assert.Equalf(t, tt.want, parseSubPath(tt.args.v), "parseSubPath(%v)", tt.args.v)
		})
	}
}

func Test_getSubPath(t *testing.T) {
	type args struct {
		envValue string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Empty",
			args: args{
				envValue: "",
			},
			want: "/",
		},
		{
			name: "Slash",
			args: args{
				envValue: "/",
			},
			want: "/",
		},
		{
			name: "Valid Value",
			args: args{
				envValue: "/subpath/",
			},
			want: "/subpath/",
		},
		{
			name: "No starting slash",
			args: args{
				envValue: "subpath/",
			},
			want: "/subpath/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			t.Setenv(SubPath, tt.args.envValue)
			defer os.Unsetenv(SubPath)
			subPathOnce = sync.Once{}
			assert.Equalf(t, tt.want, getSubPath(), "getSubPath()")
		})
	}
}

func Test_debugLogURL(t *testing.T) {
	const token = "aHR0cDovL3NvbWV1cmw"
	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{
			name:   "No credentials",
			target: "/api/v1/buckets?limit=10&prefix=a%2Fb",
			want:   "/api/v1/buckets?limit=10&prefix=a%2Fb",
		},
		{
			name:   "STS credentials for the index page",
			target: "/?sts=session-token&sts_a=access-key&sts_s=secret-key&ov_st=styles",
			want:   "/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED&ov_st=styles",
		},
		{
			name:   "Escaped parameter name",
			target: "/?st%73=session-token",
			want:   "/?st%73=REDACTED",
		},
		{
			name:   "Parameter name in upper case",
			target: "/?STS=session-token",
			want:   "/?STS=REDACTED",
		},
		{
			name:   "Parameter name that cannot be unescaped",
			target: "/?st%zzs=session-token&cp=y",
			want:   "/?st%zzs=REDACTED&cp=y",
		},
		{
			name:   "Repeated parameter",
			target: "/?sts=one&cp=y&sts=two",
			want:   "/?sts=REDACTED&cp=y&sts=REDACTED",
		},
		{
			name:   "Empty value",
			target: "/?sts=&cp=y",
			want:   "/?sts=REDACTED&cp=y",
		},
		{
			name:   "Parameter without a value",
			target: "/?sts&cp=y",
			want:   "/?sts&cp=y",
		},
		{
			name:   "Value with a semicolon",
			target: "/?sts=session;token&cp=y",
			want:   "/?sts=REDACTED&cp=y",
		},
		{
			name:   "Value with a number sign",
			target: "/?sts=session-token&sts_a=access-key&sts_s=#secret-key",
			want:   "/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:   "Parameters after a number sign",
			target: "/?x=#f&sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:   "/?x=#f&sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:   "Number sign in the path",
			target: "/#x?sts=session-token",
			want:   "/%23x?sts=REDACTED",
		},
		{
			name:   "Parameter after a semicolon",
			target: "/?x=1;sts_s=secret-key&cp=y",
			want:   "/?x=1;sts_s=REDACTED&cp=y",
		},
		{
			name:   "Token in place of the Authorization header",
			target: "/api/v1/session?access_token=claims",
			want:   "/api/v1/session?access_token=REDACTED",
		},
		{
			name: "Presigned S3 request",
			target: "/bucket/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access-key%2F20261115%2Fus-east-1%2Fs3%2Faws4_request" +
				"&X-Amz-Security-Token=session-token&X-Amz-Signature=signature",
			want: "/bucket/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED" +
				"&X-Amz-Security-Token=REDACTED&X-Amz-Signature=REDACTED",
		},
		{
			name:   "Presigned S3 request with a signature of version 2",
			target: "/bucket/object?AWSAccessKeyId=access-key&Expires=1763300000&Signature=signature",
			want:   "/bucket/object?AWSAccessKeyId=REDACTED&Expires=1763300000&Signature=REDACTED",
		},
		{
			name:   "Fields of the login request sent as parameters",
			method: http.MethodPost,
			target: "/api/v1/login?accessKey=access-key&secretKey=secret-key",
			want:   "/api/v1/login?accessKey=REDACTED&secretKey=REDACTED",
		},
		{
			name:   "Shared object",
			target: "/api/v1/download-shared-object/" + token,
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object after a dot segment",
			target: "/api/v1/download-shared-object/./" + token,
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object after two slashes",
			target: "/api/v1/download-shared-object//" + token,
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object reached through a parent segment",
			target: "/api/v1/buckets/../download-shared-object/" + token,
			want:   "/api/v1/buckets/../download-shared-object/REDACTED",
		},
		{
			name:   "Shared object in a path that matches no route",
			target: "/api/v1/download-shared-object/" + token + "/../../missing",
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object with the segment in another case",
			target: "/api/v1/Download-Shared-Object/" + token,
			want:   "/api/v1/Download-Shared-Object/REDACTED",
		},
		{
			name:   "Shared object with an escaped character in the segment",
			target: "/api/v1/download-shared-objec%74/" + token,
			want:   "/api/v1/download-shared-objec%74/REDACTED",
		},
		{
			name:   "Shared object after an escaped slash",
			target: "/api/v1/download-shared-object%2F" + token,
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object after two slashes at the start of the path",
			target: "//download-shared-object/" + token,
			want:   "//download-shared-object/REDACTED",
		},
		{
			name:   "Shared object after two slashes at the start of the path of the API",
			target: "//api/v1/download-shared-object/" + token,
			want:   "//api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object followed by another segment",
			target: "/api/v1/download-shared-object/" + token + "/extra",
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object under a subpath with an escaped character",
			target: "/console/sub%20path/api/v1/download-shared-object/" + token,
			want:   "/console/sub%20path/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Object listing whose prefix looks like a shared object",
			target: "/api/v1/buckets/b/objects?prefix=api/v1/download-shared-object/manual.pdf",
			want:   "/api/v1/buckets/b/objects?prefix=api/v1/download-shared-object/manual.pdf",
		},
		{
			name:   "Any other path with a segment of that name",
			target: "/browser/download-shared-object/bWFudWFsLnBkZg",
			want:   "/browser/download-shared-object/REDACTED",
		},
		{
			name:   "Path with that name inside a longer segment",
			target: "/browser/my-download-shared-object/bWFudWFsLnBkZg",
			want:   "/browser/my-download-shared-object/bWFudWFsLnBkZg",
		},
		{
			name:   "Path that ends with the segment",
			target: "/api/v1/download-shared-object/",
			want:   "/api/v1/download-shared-object/",
		},
		{
			name:   "Password in an absolute URL",
			target: "http://alice:password@console.example.com/?sts=session-token",
			want:   "http://alice:REDACTED@console.example.com/?sts=REDACTED",
		},
		{
			name:   "Password in the authority of a CONNECT request",
			method: http.MethodConnect,
			target: "alice:password@console.example.com:443",
			want:   "//alice:REDACTED@console.example.com:443",
		},
		{
			name:   "Opaque URL",
			target: "https:api/v1/download-shared-object/" + token + "?sts=session-token",
			want:   "https:api/v1/download-shared-object/REDACTED?sts=REDACTED",
		},
		{
			name:   "Opaque URL with an escaped character in the segment",
			target: "https:api/v1/download-shared-objec%74/" + token,
			want:   "https:api/v1/download-shared-objec%74/REDACTED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			// httptest.NewRequest reads the request line as the server does.
			r := httptest.NewRequest(method, tt.target, nil)
			assert.Equal(t, tt.want, debugLogURL(r.URL))
		})
	}
	assert.Equal(t, "", debugLogURL(nil))
}

func Test_debugLogHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "Header without credentials",
			key:   "Accept",
			value: "text/html,application/xhtml+xml;q=0.9",
			want:  "text/html,application/xhtml+xml;q=0.9",
		},
		{
			name:  "Header that is not a URL",
			key:   "User-Agent",
			value: "client sts=ready revision=2",
			want:  "client sts=ready revision=2",
		},
		{
			name:  "Authorization",
			key:   "Authorization",
			value: "Bearer secret",
			want:  "REDACTED",
		},
		{
			name:  "Key that is not canonical",
			key:   "set-cookie",
			value: "token=secret; Path=/; HttpOnly",
			want:  "REDACTED",
		},
		{
			name:  "Session token of an S3 request",
			key:   "X-Amz-Security-Token",
			value: "session-token",
			want:  "REDACTED",
		},
		{
			name:  "Referer without credentials",
			key:   "Referer",
			value: "https://console.example.com/browser/bucket?prefix=a%2Fb#top",
			want:  "https://console.example.com/browser/bucket?prefix=a%2Fb#top",
		},
		{
			name:  "Referer with credentials",
			key:   "Referer",
			value: "https://console.example.com/?sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "https://console.example.com/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "Referer with a password",
			key:   "Referer",
			value: "https://alice:p@ssword@console.example.com:9090/browser",
			want:  "https://alice:REDACTED@console.example.com:9090/browser",
		},
		{
			name:  "Referer with a password and no scheme",
			key:   "Referer",
			value: "//alice:password@console.example.com/browser",
			want:  "//alice:REDACTED@console.example.com/browser",
		},
		{
			name:  "Referer with a presigned S3 URL with a signature of version 2",
			key:   "Referer",
			value: "https://minio.example.com/bucket/object?AWSAccessKeyId=access-key&Expires=1763300000&Signature=signature",
			want:  "https://minio.example.com/bucket/object?AWSAccessKeyId=REDACTED&Expires=1763300000&Signature=REDACTED",
		},
		{
			name:  "Referer with a shared object in an opaque URL with an escaped character",
			key:   "Referer",
			value: "https:api/v1/download-shared-objec%74/aHR0cDovL3NvbWV1cmw",
			want:  "https:api/v1/download-shared-objec%74/REDACTED",
		},
		{
			name:  "Referer with a shared object after two slashes and no scheme",
			key:   "Referer",
			value: "//download-shared-object/aHR0cDovL3NvbWV1cmw",
			want:  "//download-shared-object/REDACTED",
		},
		{
			name:  "Referer with a shared object and a password",
			key:   "Referer",
			value: "https://alice:password@console.example.com/api/v1/download-shared-object/aHR0cDovL3NvbWV1cmw",
			want:  "https://alice:REDACTED@console.example.com/api/v1/download-shared-object/REDACTED",
		},
		{
			name:  "Referer with a segment that cannot be unescaped",
			key:   "Referer",
			value: "https://console.example.com/a%zz/download-shared-object/aHR0cDovL3NvbWV1cmw",
			want:  "REDACTED",
		},
		{
			name:  "Referer that is not a valid URL",
			key:   "Referer",
			value: "%zz?sts=session-token",
			want:  "REDACTED",
		},
		{
			name:  "Location of the redirect from /index.html",
			key:   "Location",
			value: "./?sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "./?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "Location of the redirect, with a number sign before the parameters",
			key:   "Location",
			value: "./?x=#f&sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "./?x=#f&sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "Referer with parameters in its fragment",
			key:   "Referer",
			value: "https://console.example.com/callback#access_token=claims&state=x",
			want:  "https://console.example.com/callback#access_token=REDACTED&state=x",
		},
		{
			name:  "Request line passed on by a reverse proxy, with a number sign in a value",
			key:   "X-Original-URI",
			value: "/console/?sts=session-token&sts_a=access-key&sts_s=#secret-key",
			want:  "/console/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "URL with a port in a header that is not in the list",
			key:   "Origin",
			value: "https://console.example.com:9090",
			want:  "https://console.example.com:9090",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, debugLogHeaderValue(tt.key, tt.value))
		})
	}
}

func Test_debugLogHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Accept", "application/json")
	h.Set("Authorization", `Bearer  {"stsAccessKeyID":"access-key","stsSecretAccessKey":"secret-key"}`)
	h.Set("Cookie", "token=session-cookie")
	h.Add("Set-Cookie", "token=session-cookie; Path=/; HttpOnly")
	h.Add("Set-Cookie", "other=value")

	var sb strings.Builder
	debugLogHeaders(&sb, h)

	indent := strings.Repeat(" ", 20)
	want := "Accept: application/json\n" +
		indent + "Authorization: REDACTED\n" +
		indent + "Cookie: REDACTED\n" +
		indent + "Set-Cookie: REDACTED\n" +
		indent + "Set-Cookie: REDACTED\n"
	assert.Equal(t, want, sb.String())
}

// AuthenticationMiddleware adds the decrypted session token to the request as its Authorization
// header, and DebugLogMiddleware, which wraps it, logs the request afterwards.
func Test_debugLog_sessionToken(t *testing.T) {
	creds := &credentials.Value{
		AccessKeyID:     "sts-access-key",
		SecretAccessKey: "sts-secret-key",
		SessionToken:    "sts-session-token",
	}
	token, err := auth.NewEncryptedTokenForClient(creds, "account-access-key", nil)
	assert.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	rw := logger.NewResponseWriter(httptest.NewRecorder())
	AuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "token", Value: token})
	})).ServeHTTP(rw, r)
	assert.Contains(t, r.Header.Get("Authorization"), creds.SecretAccessKey)

	details := debugLogDetailsText(r, rw)
	for _, text := range []string{debugLogSummaryText(r, rw), details} {
		for _, secret := range []string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, token} {
			assert.NotContains(t, text, secret)
		}
	}
	assert.Contains(t, details, "Authorization: REDACTED\n")
	assert.Contains(t, details, "Cookie: REDACTED\n")
	assert.Contains(t, details, "Set-Cookie: REDACTED\n")
}

// The file server redirects /index.html to / and repeats the query in the Location header.
func Test_debugLog_indexRedirect(t *testing.T) {
	secrets := []string{"sts-session-token", "sts-access-key", "sts-secret-key"}
	r := httptest.NewRequest(http.MethodGet, "/index.html?sts="+secrets[0]+"&sts_a="+secrets[1]+"&sts_s="+secrets[2], nil)
	rw := logger.NewResponseWriter(httptest.NewRecorder())
	FileServerMiddleware(http.NotFoundHandler()).ServeHTTP(rw, r)
	assert.Equal(t, http.StatusMovedPermanently, rw.StatusCode)
	assert.Contains(t, rw.Header().Get("Location"), secrets[2])

	details := debugLogDetailsText(r, rw)
	for _, text := range []string{debugLogSummaryText(r, rw), details} {
		for _, secret := range secrets {
			assert.NotContains(t, text, secret)
		}
	}
	assert.Contains(t, details, "Location: ./?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED\n")
}

// Requests that carry credentials go through all the middleware and the router of the API, as
// they do in the server, and what DebugLogMiddleware logs is read. No handler that contacts
// MinIO is reached: the requests are answered by the file server, fail to find a route, fail
// authentication, or ask for a shared object whose URL does not point to MinIO.
func Test_debugLog_server(t *testing.T) {
	creds := &credentials.Value{
		AccessKeyID:     "sts-access-key",
		SecretAccessKey: "sts-secret-key",
		SessionToken:    "sts-session-token",
	}
	cookie, err := auth.NewEncryptedTokenForClient(creds, "account-access-key", nil)
	assert.NoError(t, err)
	presigned := "http://other.example.com/bucket/object?X-Amz-Signature=presigned-signature"
	sharedObject := base64.RawURLEncoding.EncodeToString([]byte(presigned))
	stsParams := "sts=" + creds.SessionToken + "&sts_a=" + creds.AccessKeyID + "&sts_s=" + creds.SecretAccessKey
	secrets := []string{
		creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, cookie, sharedObject,
		"basic-credentials", "access-token-claims", "number-sign-secret", "semicolon-secret",
		"login-access-key", "login-secret-key",
	}

	get := func(target string) *http.Request {
		return httptest.NewRequest(http.MethodGet, target, nil)
	}
	withCookie := func(r *http.Request) *http.Request {
		r.AddCookie(&http.Cookie{Name: "token", Value: cookie})
		return r
	}
	tests := []struct {
		name    string
		request func() *http.Request
		status  int
	}{
		{
			name:    "Session cookie",
			request: func() *http.Request { return withCookie(get("/api/v1/no-such-route")) },
			status:  http.StatusNotFound,
		},
		{
			name: "Token in the query next to an Authorization header that is not a Bearer one",
			request: func() *http.Request {
				r := get("/api/v1/buckets?access_token=access-token-claims")
				r.Header.Set("Authorization", "Basic basic-credentials")
				return r
			},
			status: http.StatusUnauthorized,
		},
		{
			name:    "STS credentials for the index page",
			request: func() *http.Request { return get("/?" + stsParams) },
			status:  http.StatusOK,
		},
		{
			name:    "STS credentials on the redirect from /index.html",
			request: func() *http.Request { return get("/index.html?" + stsParams) },
			status:  http.StatusMovedPermanently,
		},
		{
			name:    "STS credentials after a number sign on the redirect from /index.html",
			request: func() *http.Request { return get("/index.html?x=#f&" + stsParams) },
			status:  http.StatusMovedPermanently,
		},
		{
			name:    "Number sign in a value",
			request: func() *http.Request { return get("/?sts=s&sts_a=a&sts_s=#number-sign-secret") },
			status:  http.StatusOK,
		},
		{
			name:    "Parameter after a semicolon",
			request: func() *http.Request { return get("/?x=1;sts_s=semicolon-secret") },
			status:  http.StatusOK,
		},
		{
			name:    "Shared object",
			request: func() *http.Request { return get("/api/v1/download-shared-object/" + sharedObject) },
			status:  http.StatusForbidden,
		},
		{
			name:    "Shared object after a dot segment",
			request: func() *http.Request { return get("/api/v1/download-shared-object/./" + sharedObject) },
			status:  http.StatusForbidden,
		},
		{
			name:    "Shared object after two slashes",
			request: func() *http.Request { return get("/api/v1/download-shared-object//" + sharedObject) },
			status:  http.StatusForbidden,
		},
		{
			name: "Shared object in a path that matches no route",
			request: func() *http.Request {
				return get("/api/v1/download-shared-object/" + sharedObject + "/../../missing")
			},
			status: http.StatusNotFound,
		},
		{
			name:    "Shared object after two slashes at the start of the path",
			request: func() *http.Request { return get("//download-shared-object/" + sharedObject) },
			status:  http.StatusOK,
		},
		{
			name: "Fields of the login request sent as parameters, without a body",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/v1/login?accessKey=login-access-key&secretKey=login-secret-key", nil)
			},
			status: http.StatusUnprocessableEntity,
		},
		{
			name: "Websocket handshake",
			request: func() *http.Request {
				r := withCookie(get("/ws/objectManager"))
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				return r
			},
			status: http.StatusInternalServerError,
		},
	}

	for level, wanted := range map[string][]string{
		"3": {
			"/index.html?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED ",
			"/index.html?x=#f&sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED ",
			"/api/v1/download-shared-object/REDACTED ",
			"//download-shared-object/REDACTED ",
			"/api/v1/login?accessKey=REDACTED&secretKey=REDACTED ",
			"/?x=1;sts_s=REDACTED ",
		},
		"6": {
			"Location: ./?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED\n",
			"Location: ./?x=#f&sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED\n",
			"Authorization: REDACTED\n",
			"Cookie: REDACTED\n",
			"Set-Cookie: REDACTED\n",
		},
	} {
		t.Run("Level "+level, func(t *testing.T) {
			t.Setenv("CONSOLE_DEBUG_LOGLEVEL", level)
			var logged []string
			original := debugLogInfo
			debugLogInfo = func(text string) { logged = append(logged, text) }
			defer func() { debugLogInfo = original }()

			spec, err := loads.Embedded(SwaggerJSON, FlatSwaggerJSON)
			assert.NoError(t, err)
			consoleAPI := operations.NewConsoleAPI(spec)
			var apiLog []string
			consoleAPI.Logger = func(format string, args ...interface{}) {
				apiLog = append(apiLog, fmt.Sprintf(format, args...))
			}
			handler := configureAPI(consoleAPI)

			for _, tt := range tests {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, tt.request())
				assert.Equal(t, tt.status, w.Code, tt.name)
			}
			// The API read the token from the query: it reports that it could not validate it.
			assert.Contains(t, strings.Join(apiLog, "\n"), "access-token-claims")

			assert.Len(t, logged, len(tests))
			text := strings.Join(logged, "\n")
			for _, secret := range secrets {
				assert.NotContains(t, text, secret)
			}
			for _, want := range wanted {
				assert.Contains(t, text, want)
			}
		})
	}
}

// A websocket handshake that succeeds. The server hands the connection over to the websocket,
// and DebugLogMiddleware logs the request when the handler returns. No handler serves the path
// of the request, so the server closes the websocket as soon as it is open and creates no MinIO
// client.
func Test_debugLog_websocket(t *testing.T) {
	creds := &credentials.Value{
		AccessKeyID:     "sts-access-key",
		SecretAccessKey: "sts-secret-key",
		SessionToken:    "sts-session-token",
	}
	cookie, err := auth.NewEncryptedTokenForClient(creds, "account-access-key", nil)
	assert.NoError(t, err)

	t.Setenv("CONSOLE_DEBUG_LOGLEVEL", "6")
	logged := make(chan string, 1)
	original := debugLogInfo
	debugLogInfo = func(text string) { logged <- text }
	defer func() { debugLogInfo = original }()

	spec, err := loads.Embedded(SwaggerJSON, FlatSwaggerJSON)
	assert.NoError(t, err)
	consoleAPI := operations.NewConsoleAPI(spec)
	consoleAPI.Logger = func(string, ...interface{}) {}
	server := httptest.NewServer(configureAPI(consoleAPI))
	defer server.Close()

	address := server.Listener.Addr().String()
	conn, err := net.Dial("tcp", address)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /ws/none?sts_s=query-secret HTTP/1.1\r\nHost: %s\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCookie: token=%s\r\n\r\n", address, cookie)
	assert.NoError(t, err)
	status, err := bufio.NewReader(conn).ReadString('\n')
	assert.NoError(t, err)
	assert.Contains(t, status, " 101 ")

	select {
	case text := <-logged:
		assert.Contains(t, text, "GET /ws/none?sts_s=REDACTED\n")
		assert.Contains(t, text, "<hijacked, probably a websocket>")
		assert.Contains(t, text, "Authorization: REDACTED\n")
		assert.Contains(t, text, "Cookie: REDACTED\n")
		for _, secret := range []string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, cookie, "query-secret"} {
			assert.NotContains(t, text, secret)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the debug log did not record the request")
	}
}
