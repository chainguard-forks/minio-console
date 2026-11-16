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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/minio/console/api/operations"
	"github.com/minio/console/pkg/auth"
	xjwt "github.com/minio/console/pkg/auth/token"
	"github.com/minio/console/pkg/logger"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/pbkdf2"
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
			name:   "Name that cannot be unescaped and holds a question mark",
			target: "/?bad%zz?name=value&cp=y",
			want:   "/?bad%zz?name=REDACTED&cp=y",
		},
		{
			name:   "Name that cannot be unescaped and holds a number sign",
			target: "/?bad%zz#name=value&cp=y",
			want:   "/?bad%zz#name=REDACTED&cp=y",
		},
		{
			name:   "Name that cannot be unescaped and holds a semicolon, after another parameter",
			target: "/?a=b;bad%zz;name=value&cp=y",
			want:   "/?a=b;bad%zz;name=REDACTED&cp=y",
		},
		{
			name:   "Value that cannot be unescaped, before another parameter",
			target: "/?a=%zz;name=value&cp=y",
			want:   "/?a=%zz;name=value&cp=y",
		},
		{
			name:   "Text that cannot be unescaped, without a value",
			target: "/?bad%zz&cp=y",
			want:   "/?bad%zz&cp=y",
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
			name:   "One of the names after a question mark in the value of another parameter",
			target: "/?next=https://example.test/?sts=ready&cp=y",
			want:   "/?next=https://example.test/?sts=REDACTED&cp=y",
		},
		{
			name:   "Limit: a password in a URL that is the value of a parameter is not recognized",
			target: "/?next=https://alice:password@minio.example/",
			want:   "/?next=https://alice:password@minio.example/",
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
			name:   "Shared object with a number sign in its presigned URL",
			target: "/api/v1/download-shared-object/aHR0c#DovL3NvbWV1cmw",
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object after an escaped slash",
			target: "/api/v1/download-shared-object%2F" + token,
			want:   "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:   "Shared object in a path whose slashes are all escaped",
			target: "/api%2Fv1%2fdownload-shared-object%2f" + token,
			want:   "/api%2Fv1%2fdownload-shared-object/REDACTED",
		},
		{
			name:   "Escaped slash after the segment and nothing else",
			target: "/api/v1/download-shared-object%2F",
			want:   "/api/v1/download-shared-object%2F",
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
			name:   "Opaque URL that begins with the segment",
			target: "https:download-shared-object/" + token,
			want:   "https:download-shared-object/REDACTED",
		},
		{
			name:   "Opaque URL that begins with the segment, with an escaped character",
			target: "https:Download-shared-objec%74/" + token + "?sts=session-token",
			want:   "https:Download-shared-objec%74/REDACTED?sts=REDACTED",
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

// A request line can be as long as the server allows, and anyone can send one. The memory that
// debugLogURLText allocates for a text must grow with its length and not faster: for a text four
// times as long, it must stay under eight times as much. An earlier version did work that grew
// with the square of the length for the first five of these texts, which is sixteen times as
// much.
//
// The test measures memory and not time, so it does not notice work that allocates nothing.
//
// The counter it reads belongs to the whole process. The test therefore runs on one processor,
// as testing.AllocsPerRun does: no other goroutine runs while a text is measured, unless the
// scheduler interrupts the measurement, which takes about a millisecond. Each measurement is
// the smallest of three, against such an interruption. What another goroutine allocates during
// all three would still be counted.
func Test_debugLogURLText_longText(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	const marker = "download-shared-object"
	tests := []struct {
		name string
		text func(count int) string
		want func(count int) string
	}{
		{
			name: "Slashes",
			text: func(count int) string { return strings.Repeat("/", count) },
			want: func(count int) string { return strings.Repeat("/", count) },
		},
		{
			name: "Escaped slashes",
			text: func(count int) string { return "/" + strings.Repeat("%2F", count) },
			want: func(count int) string { return "/" + strings.Repeat("%2F", count) },
		},
		{
			name: "Segment of a shared object followed by slashes only",
			text: func(count int) string { return "/" + marker + strings.Repeat("/", count) },
			want: func(count int) string { return "/" + marker + strings.Repeat("/", count) },
		},
		{
			name: "Segment of a shared object, repeated",
			text: func(count int) string { return strings.Repeat("/"+marker, count) },
			want: func(int) string { return "/" + marker + "/REDACTED" },
		},
		{
			name: "Segment of a shared object after escaped slashes, repeated",
			text: func(count int) string { return "/" + strings.Repeat("%2F"+marker, count) },
			want: func(int) string { return "/%2F" + marker + "/REDACTED" },
		},
		{
			name: "Parameters",
			text: func(count int) string { return "/?" + strings.Repeat("a=b&", count) },
			want: func(count int) string { return "/?" + strings.Repeat("a=b&", count) },
		},
		{
			name: "Separators in one parameter",
			text: func(count int) string { return "/?a=b" + strings.Repeat(";", count) + "sts=session-token" },
			want: func(count int) string { return "/?a=b" + strings.Repeat(";", count) + "sts=REDACTED" },
		},
	}
	allocated := func(text string) uint64 {
		smallest := uint64(math.MaxUint64)
		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			debugLogURLText(text)
			runtime.ReadMemStats(&after)
			smallest = min(smallest, after.TotalAlloc-before.TotalAlloc)
		}
		return smallest
	}
	const count = 5000
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			long := tt.text(4 * count)
			assert.True(t, tt.want(4*count) == debugLogURLText(long), "unexpected text for %d separators", 4*count)
			assert.Less(t, allocated(long), 8*allocated(tt.text(count)))
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
			name:  "Referer with a shared object whose presigned URL cannot be unescaped",
			key:   "Referer",
			value: "https://console.example.com/download-shared-object/%zz",
			want:  "REDACTED",
		},
		{
			name:  "Referer with a host that cannot be parsed, which would be one without what follows the segment",
			key:   "Referer",
			value: "https://download-shared-object%2Ftoken/path",
			want:  "REDACTED",
		},
		{
			name:  "Referer without a scheme whose first segment holds an escaped colon before the name",
			key:   "Referer",
			value: "folder%3Adownload-shared-object/manual.pdf",
			want:  "folder%3Adownload-shared-object/manual.pdf",
		},
		{
			name:  "Request line passed on by a reverse proxy, with a colon before the name after a number sign",
			key:   "X-Original-URI",
			value: "x#a:download-shared-object/manual.pdf",
			want:  "x#a:download-shared-object/manual.pdf",
		},
		{
			name:  "Referer with a shared object in an opaque URL that begins with the segment, scheme in upper case",
			key:   "Referer",
			value: "HTTPS:download-shared-object/aHR0cDovL3NvbWV1cmw",
			want:  "HTTPS:download-shared-object/REDACTED",
		},
		{
			name:  "Referer with a shared object in an opaque URL that begins with the segment",
			key:   "Referer",
			value: "https:download-shared-object/aHR0cDovL3NvbWV1cmw",
			want:  "https:download-shared-object/REDACTED",
		},
		{
			name:  "Limit: a header that is not in the list is not searched",
			key:   "X-Custom-Url",
			value: "https://alice:password@console.example.com/?sts=session-token",
			want:  "https://alice:password@console.example.com/?sts=session-token",
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
			name:  "Request line passed on by a reverse proxy, with a number sign in the presigned URL of a shared object",
			key:   "X-Original-URI",
			value: "/api/v1/download-shared-object/aHR0c#DovL3NvbWV1cmw",
			want:  "/api/v1/download-shared-object/REDACTED",
		},
		{
			name:  "Request line passed on by a reverse proxy, with a shared object after a number sign",
			key:   "X-Original-URI",
			value: "/console#/api/v1/download-shared-object/aHR0cDovL3NvbWV1cmw?sts=session-token",
			want:  "/console#/api/v1/download-shared-object/REDACTED?sts=REDACTED",
		},
		{
			name:  "Referer with a fragment that cannot be unescaped",
			key:   "Referer",
			value: "https://console.example.com/browser#50%",
			want:  "REDACTED",
		},
		{
			name:  "Referer with a query that cannot be unescaped",
			key:   "Referer",
			value: "https://console.example.com/browser?discount=50%&sts=session-token",
			want:  "https://console.example.com/browser?discount=50%&sts=REDACTED",
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

// The logger formats what it is given. A "%" in a URL must reach the output of the logger as it
// is, in the summary and in the details. The other tests replace debugLogInfo and do not see
// what the logger makes of a text; this one reads the output of the logger.
//
// It reads the output of the logger's default mode, which the console package writes to
// color.Output. The JSON mode formats the same format and argument with fmt.Sprintf and prints
// to the standard output; it is not tested here, because the logger has no way to leave that
// mode again.
func Test_debugLog_output(t *testing.T) {
	var output bytes.Buffer
	original := color.Output
	color.Output = &output
	defer func() { color.Output = original }()

	r := httptest.NewRequest(http.MethodGet, "/browser/a%2Fb?prefix=c%2Fd&format=%s%d&sts=session-token", nil)
	r.Header.Set("Referer", "https://console.example.com/browser/a%2Fb")
	rw := logger.NewResponseWriter(httptest.NewRecorder())
	debugLogSummary(r, rw)
	debugLogDetails(r, rw)

	text := output.String()
	assert.Equal(t, 2, strings.Count(text, " /browser/a%2Fb?prefix=c%2Fd&format=%s%d&sts=REDACTED"))
	assert.Contains(t, text, "Referer: https://console.example.com/browser/a%2Fb\n")
	assert.NotContains(t, text, "session-token")
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
			// The API read the token from the query: it reports that it could not validate it,
			// and does not show it. No other request of the table carries a token that fails.
			assert.Equal(t, []string{keyAuthNotJSON}, apiLog)

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

	// One deadline for the connection, the handshake and the wait for the log together, so that
	// an exchange that stalls at any point fails the test.
	deadline := time.Now().Add(10 * time.Second)
	address := server.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", address, time.Until(deadline))
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()
	assert.NoError(t, conn.SetDeadline(deadline))
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
	case <-time.After(time.Until(deadline)):
		t.Fatal("the debug log did not record the request")
	}
}

// What KeyAuth logs for a token that it cannot validate.
const (
	keyAuthNotJSON   = "Unable to validate the session token: it is not valid JSON"
	keyAuthOtherForm = "Unable to validate the session token: its JSON does not have the form of a session's claims"
)

// newLoggedAPI returns the API and its handler, as the server configures them, and the messages
// that the API logs.
func newLoggedAPI(t *testing.T) (*operations.ConsoleAPI, http.Handler, *[]string) {
	spec, err := loads.Embedded(SwaggerJSON, FlatSwaggerJSON)
	assert.NoError(t, err)
	consoleAPI := operations.NewConsoleAPI(spec)
	logged := &[]string{}
	consoleAPI.Logger = func(format string, args ...interface{}) {
		*logged = append(*logged, fmt.Sprintf(format, args...))
	}
	return consoleAPI, configureAPI(consoleAPI), logged
}

// KeyAuth logs that it could not validate a token, and answers 401. The message must hold
// nothing of the token: not the token, and not the text of the decoding error, which can quote
// from it. A JSON syntax error can name the character that it did not expect, as it does for
// the first token here. The whole message is compared, so that no part of a token can be in it.
func Test_KeyAuth_invalidToken(t *testing.T) {
	const claims = `{"stsAccessKeyID":"sts-access-key","stsSecretAccessKey":"sts-secret-key","stsSessionToken":"sts-session-token"`
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "Text that is not JSON",
			token: "opaque-bearer-token",
			want:  keyAuthNotJSON,
		},
		{
			name:  "Claims that are cut short",
			token: claims,
			want:  keyAuthNotJSON,
		},
		{
			name:  "Claims followed by other text",
			token: claims + "}sts-secret-key",
			want:  keyAuthNotJSON,
		},
		{
			name:  "Claim of another type",
			token: claims + `,"hm":"yes"}`,
			want:  keyAuthOtherForm,
		},
		{
			name:  "JSON that is not an object",
			token: `["sts-secret-key"]`,
			want:  keyAuthOtherForm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consoleAPI, _, logged := newLoggedAPI(t)
			principal, err := consoleAPI.KeyAuth(tt.token, nil)
			assert.Nil(t, principal)
			var apiErr errors.Error
			if assert.ErrorAs(t, err, &apiErr) {
				assert.Equal(t, int32(http.StatusUnauthorized), apiErr.Code())
			}
			assert.Equal(t, []string{tt.want}, *logged)
		})
	}
}

// sessionTokenProblem chooses its text by the type of the error, also when another error wraps
// the decoding error, and it has a text for any other error. The text of the error is in none
// of them.
func Test_sessionTokenProblem(t *testing.T) {
	const token = "opaque-bearer-token"
	_, syntaxErr := auth.ParseClaimsFromToken(token)
	_, typeErr := auth.ParseClaimsFromToken(`{"hm":"` + token + `"}`)
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "Syntax error",
			err:  syntaxErr,
			want: "it is not valid JSON",
		},
		{
			name: "Type error",
			err:  typeErr,
			want: "its JSON does not have the form of a session's claims",
		},
		{
			name: "Error that wraps a syntax error",
			err:  fmt.Errorf("claims of %s: %w", token, syntaxErr),
			want: "it is not valid JSON",
		},
		{
			name: "Any other error",
			err:  fmt.Errorf("no claims in %s", token),
			want: "it could not be decoded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if assert.Error(t, tt.err) {
				assert.Equal(t, tt.want, sessionTokenProblem(tt.err))
			}
		})
	}
}

// sessionCookieOf returns a session cookie that holds the given text in place of the claims of a
// session. The console has no function that makes one, because it encrypts claims only. So the
// text is encrypted here as encrypt in pkg/auth does it with AES-GCM, and the test fails unless
// the console decrypts the cookie to that text. The IV and the nonce are zeros: nothing here
// depends on them.
func sessionCookieOf(t *testing.T, text string) string {
	key := pbkdf2.Key([]byte(xjwt.GetPBKDFPassphrase()), []byte(xjwt.GetPBKDFSalt()), 4096, 32, sha1.New)
	iv := make([]byte, 16)
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	block, err := aes.NewCipher(mac.Sum(nil))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	aead, err := cipher.NewGCM(block)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	nonce := make([]byte, aead.NonceSize())
	// The identifier of AES-GCM, the IV, the nonce and the sealed text.
	ciphertext := append([]byte{0x00}, iv...)
	ciphertext = append(ciphertext, nonce...)
	ciphertext = aead.Seal(ciphertext, nonce, []byte(text), []byte{})
	cookie := base64.StdEncoding.EncodeToString(ciphertext)

	decrypted, err := auth.DecryptToken(cookie)
	assert.NoError(t, err)
	assert.Equal(t, text, string(decrypted))
	return cookie
}

// The values that reach KeyAuth and fail there, sent through all the middleware and the router
// of the API, as the server sets them up. The API takes the token from the first Authorization
// header of the request when that begins with "Bearer ", else from the access_token parameter
// of the query, else from that of a form. AuthenticationMiddleware adds its own Authorization
// header after those of the client: "Bearer Anonymous", or the decrypted session cookie. So the
// token that fails is a value that the client sent, or the text of a session cookie that is not
// the claims of a session.
func Test_KeyAuth_invalidToken_server(t *testing.T) {
	const secret = "client-sent-secret"
	creds := &credentials.Value{
		AccessKeyID:     "sts-access-key",
		SecretAccessKey: "sts-secret-key",
		SessionToken:    "sts-session-token",
	}
	session, err := auth.NewEncryptedTokenForClient(creds, "account-access-key", nil)
	assert.NoError(t, err)
	const otherClaims = `{"stsAccessKeyID":"sts-access-key","stsSecretAccessKey":"sts-secret-key","hm":"yes"}`
	otherSession := sessionCookieOf(t, otherClaims)

	tests := []struct {
		name    string
		request func() *http.Request
		want    string
	}{
		{
			name: "Authorization header of the client",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
				r.Header.Set("Authorization", "Bearer "+secret)
				return r
			},
			want: keyAuthNotJSON,
		},
		{
			name: "Authorization header of the client next to a session cookie",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
				r.Header.Set("Authorization", "Bearer "+secret)
				r.AddCookie(&http.Cookie{Name: "token", Value: session})
				return r
			},
			want: keyAuthNotJSON,
		},
		{
			name: "Token in the query next to an Authorization header that is not a Bearer one",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/v1/session?access_token="+secret, nil)
				r.Header.Set("Authorization", "Basic basic-credentials")
				return r
			},
			want: keyAuthNotJSON,
		},
		{
			name: "Token in a form next to an Authorization header that is not a Bearer one",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/v1/buckets", strings.NewReader("access_token="+secret))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Authorization", "Basic basic-credentials")
				return r
			},
			want: keyAuthNotJSON,
		},
		{
			name: "Session cookie whose text is not the claims of a session",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
				r.AddCookie(&http.Cookie{Name: "token", Value: otherSession})
				return r
			},
			want: keyAuthOtherForm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, handler, logged := newLoggedAPI(t)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, tt.request())
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, []string{tt.want}, *logged)
		})
	}
}
