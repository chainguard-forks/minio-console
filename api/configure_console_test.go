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
			name: "Parameter without a value",
			url:  "/?sts&cp=y",
			want: "/?sts&cp=y",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, debugLogURL(u))
		})
	}
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
			value: "application/json",
			want:  "application/json",
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
			name:  "Referer that is not a URL",
			key:   "Referer",
			value: "%zz?sts=session-token",
			want:  "REDACTED",
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

// AuthenticationMiddleware adds the Authorization header to the request that DebugLogMiddleware,
// which wraps it, logs afterwards.
func Test_debugLogHeaders_afterAuthentication(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	AuthenticationMiddleware(next).ServeHTTP(httptest.NewRecorder(), r)
	assert.NotEmpty(t, r.Header.Get("Authorization"))

	var sb strings.Builder
	debugLogHeaders(&sb, r.Header)
	assert.Equal(t, "Authorization: REDACTED\n", sb.String())
}
