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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

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
			want:   "/api/v1/download-shared-object/REDACTED",
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
			name:   "Object browser path that is not a shared object",
			target: "/browser/download-shared-object/bWFudWFsLnBkZg",
			want:   "/browser/download-shared-object/bWFudWFsLnBkZg",
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
// they do in the server, and what DebugLogMiddleware logs is read.
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
	stsQuery := "?sts=" + creds.SessionToken + "&sts_a=" + creds.AccessKeyID + "&sts_s=" + creds.SecretAccessKey

	secrets := []string{
		creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, cookie, sharedObject,
		"basic-credentials", "access-token-claims", "number-sign-secret",
	}
	requests := func() []*http.Request {
		// No handler behind these requests is reached, so nothing contacts MinIO: the first route
		// does not exist, the second request fails authentication and the shared objects are
		// refused because their URL does not point to MinIO.
		withCookie := httptest.NewRequest(http.MethodGet, "/api/v1/no-such-route", nil)
		withCookie.AddCookie(&http.Cookie{Name: "token", Value: cookie})
		withAccessToken := httptest.NewRequest(http.MethodGet, "/api/v1/buckets?access_token=access-token-claims", nil)
		withAccessToken.Header.Set("Authorization", "Basic basic-credentials")
		return []*http.Request{
			withCookie,
			withAccessToken,
			httptest.NewRequest(http.MethodGet, "/"+stsQuery, nil),
			httptest.NewRequest(http.MethodGet, "/index.html"+stsQuery, nil),
			httptest.NewRequest(http.MethodGet, "/?sts=s&sts_a=a&sts_s=#number-sign-secret", nil),
			httptest.NewRequest(http.MethodGet, "/api/v1/download-shared-object/"+sharedObject, nil),
			httptest.NewRequest(http.MethodGet, "/api/v1/download-shared-object/./"+sharedObject, nil),
			httptest.NewRequest(http.MethodGet, "/api/v1/download-shared-object//"+sharedObject, nil),
		}
	}

	for level, wanted := range map[string][]string{
		"3": {"/index.html?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED", "/api/v1/download-shared-object/REDACTED"},
		"6": {"Location: ./?sts=REDACTED&sts_a=REDACTED&sts_s=REDACTED\n", "Authorization: REDACTED\n", "Cookie: REDACTED\n", "Set-Cookie: REDACTED\n"},
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
			consoleAPI.Logger = func(string, ...interface{}) {}
			handler := configureAPI(consoleAPI)
			sent := requests()
			for _, r := range sent {
				handler.ServeHTTP(httptest.NewRecorder(), r)
			}

			assert.Len(t, logged, len(sent))
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
