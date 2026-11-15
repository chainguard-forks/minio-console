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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

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
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "No credentials",
			url:  "/api/v1/buckets?limit=10&prefix=a%2Fb",
			want: "/api/v1/buckets?limit=10&prefix=a%2Fb",
		},
		{
			name: "STS credentials for the index page",
			url:  "/?sts=session-token&sts_a=access-key&sts_s=secret-key&ov_st=styles",
			want: "/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED&ov_st=styles",
		},
		{
			name: "Escaped parameter name",
			url:  "/?st%73=session-token",
			want: "/?st%73=REDACTED",
		},
		{
			name: "Parameter name in upper case",
			url:  "/?STS=session-token",
			want: "/?STS=REDACTED",
		},
		{
			name: "Repeated parameter",
			url:  "/?sts=one&cp=y&sts=two",
			want: "/?sts=REDACTED&cp=y&sts=REDACTED",
		},
		{
			name: "Empty value",
			url:  "/?sts=&cp=y",
			want: "/?sts=REDACTED&cp=y",
		},
		{
			name: "Parameter without a value",
			url:  "/?sts&cp=y",
			want: "/?sts&cp=y",
		},
		{
			name: "Value with a semicolon",
			url:  "/?sts=session;token&cp=y",
			want: "/?sts=REDACTED&cp=y",
		},
		{
			name: "Token in place of the Authorization header",
			url:  "/api/v1/session?access_token=claims",
			want: "/api/v1/session?access_token=REDACTED",
		},
		{
			name: "Presigned S3 request",
			url: "/bucket/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access-key%2F20261115%2Fus-east-1%2Fs3%2Faws4_request" +
				"&X-Amz-Security-Token=session-token&X-Amz-Signature=signature",
			want: "/bucket/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED" +
				"&X-Amz-Security-Token=REDACTED&X-Amz-Signature=REDACTED",
		},
		{
			name: "Shared object",
			url:  "/api/v1/download-shared-object/aHR0cDovL3NvbWV1cmw",
			want: "/api/v1/download-shared-object/REDACTED",
		},
		{
			name: "Shared object under a subpath",
			url:  "/console/subpath/api/v1/download-shared-object/aHR0cDovL3NvbWV1cmw",
			want: "/console/subpath/api/v1/download-shared-object/REDACTED",
		},
		{
			name: "Object browser path that is not a shared object",
			url:  "/browser/download-shared-object/bWFudWFsLnBkZg",
			want: "/browser/download-shared-object/bWFudWFsLnBkZg",
		},
		{
			name: "Password in an absolute URL",
			url:  "https://alice:password@console.example.com/?sts=session-token",
			want: "https://alice:REDACTED@console.example.com/?sts=REDACTED",
		},
		{
			name: "Opaque URL",
			url:  "https:api/v1/download-shared-object/aHR0cDovL3NvbWV1cmw?sts=session-token",
			want: "https:api/v1/download-shared-object/REDACTED?sts=REDACTED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, debugLogURL(u))
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
			value: "https://console.example.com/browser/bucket?prefix=a%2Fb",
			want:  "https://console.example.com/browser/bucket?prefix=a%2Fb",
		},
		{
			name:  "Referer with credentials",
			key:   "Referer",
			value: "https://console.example.com/?sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "https://console.example.com/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "Referer that is not a valid URL",
			key:   "Referer",
			value: "%zz?sts=session-token",
			want:  "%zz?sts=REDACTED",
		},
		{
			name:  "Referer with a password",
			key:   "Referer",
			value: "https://alice:p@ssword@console.example.com:9090/browser",
			want:  "https://alice:REDACTED@console.example.com:9090/browser",
		},
		{
			name:  "URL with a port and no password",
			key:   "Origin",
			value: "https://console.example.com:9090",
			want:  "https://console.example.com:9090",
		},
		{
			name:  "Location of the redirect from /index.html",
			key:   "Location",
			value: "./?sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "./?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
		},
		{
			name:  "URL passed on by a reverse proxy",
			key:   "X-Original-Uri",
			value: "/console/?sts=session-token&sts_a=access-key&sts_s=secret-key",
			want:  "/console/?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED",
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
