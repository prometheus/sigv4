// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

type RoundTripperFunc func(req *http.Request) (*http.Response, error)

// RoundTrip implements the RoundTripper interface.
func (rt RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

// idBody is an io.ReadCloser used through a pointer so that tests can assert
// RoundTrip never replaces the caller's req.Body field, using require.Same for
// pointer identity rather than require.Equal (which would also pass for a
// different value wrapping the same reader).
type idBody struct {
	io.Reader
}

func (idBody) Close() error { return nil }

func TestSigV4_Inferred_Region(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "secret")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "token")
	os.Setenv("AWS_REGION", "us-west-2")
	awscfg, err := config.LoadDefaultConfig(
		t.Context(),
		config.WithRegion(""),
	)

	require.NoError(t, err)
	_, err = awscfg.Credentials.Retrieve(t.Context())
	require.NoError(t, err)

	require.NotNil(t, awscfg.Region)
	require.Equal(t, "us-west-2", awscfg.Region)
}

func TestNewSigV4RoundTripperInferredRegion(t *testing.T) {
	// Region is left empty in the config so it must be inferred from the
	// environment; the resulting transport must sign with the inferred region.
	t.Setenv("AWS_ACCESS_KEY_ID", "access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "us-west-2")

	cfg := &SigV4Config{}

	rt, err := NewSigV4RoundTripper(cfg, nil, WithContext(t.Context()))
	require.NoError(t, err)

	sigRT, ok := rt.(*sigV4RoundTripper)
	require.True(t, ok)
	require.Equal(t, "us-west-2", sigRT.region)
}

func TestNewSigV4RoundTripperWithContext(t *testing.T) {
	cfg := &SigV4Config{
		Region:    "us-east-1",
		AccessKey: "access",
		SecretKey: "secret",
	}

	t.Run("live context", func(t *testing.T) {
		rt, err := NewSigV4RoundTripper(cfg, nil, WithContext(t.Context()))
		require.NoError(t, err)
		require.NotNil(t, rt)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := NewSigV4RoundTripper(cfg, nil, WithContext(ctx))
		require.Error(t, err)
	})
}

func TestSigV4RoundTripper(t *testing.T) {
	var gotReq *http.Request

	awscfg, _ := config.LoadDefaultConfig(
		t.Context(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("AccessKey", "SecretKey", "token")),
		config.WithRegion("us-east-2"),
	)
	rt := &sigV4RoundTripper{
		region: "us-east-2",
		next: RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{StatusCode: http.StatusOK}, nil
		}),
		creds:  aws.NewCredentialsCache(awscfg.Credentials),
		signer: signer.NewSigner(),
	}
	rt.pool.New = rt.newBuf

	cli := &http.Client{Transport: rt}

	req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("Hello, world!"))
	require.NoError(t, err)

	_, err = cli.Do(req)
	require.NoError(t, err)
	require.NotNil(t, gotReq)

	origReq := gotReq
	require.NotEmpty(t, origReq.Header.Get("Authorization"))
	require.NotEmpty(t, origReq.Header.Get("X-Amz-Date"))

	// Perform the same request but with a header that shouldn't included in the
	// signature; validate that the Authorization signature matches.
	t.Run("Ignored Headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("Hello, world!"))
		require.NoError(t, err)

		req.Header.Add("Uber-Trace-Id", "some-trace-id")

		_, err = cli.Do(req)
		require.NoError(t, err)
		require.NotNil(t, gotReq)
		// Validate that the transport is able to consume the body
		data, err := io.ReadAll(gotReq.Body)
		require.NoError(t, err)
		require.Equal(t, "Hello, world!", string(data))

		require.Equal(t, origReq.Header.Get("Authorization"), gotReq.Header.Get("Authorization"))
	})

	t.Run("Escape URL", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "https://example.com/test//test", strings.NewReader("Hello, world!"))
		require.NoError(t, err)
		require.Equal(t, "/test//test", req.URL.Path)

		_, err = cli.Do(req)
		require.NoError(t, err)
		require.NotNil(t, gotReq)
		// Validate that the transport is able to consume the body
		_, err = io.ReadAll(gotReq.Body)
		require.NoError(t, err)
		require.Equal(t, "/test/test", gotReq.URL.Path)
	})

	t.Run("No body", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/test/test", nil) //nolint:gocritic //nil body is intentional
		require.NoError(t, err)
		_, err = cli.Do(req)
		require.Nil(t, req.Body)
		require.NoError(t, err)
	})

	// The http.RoundTripper contract forbids modifying the caller's request.
	// Validate that neither the body nor the URL of the original request is
	// mutated by RoundTrip.
	t.Run("Caller request not mutated", func(t *testing.T) {
		body := &idBody{Reader: strings.NewReader("Hello, world!")}
		req, err := http.NewRequest(http.MethodPost, "https://example.com/test//test/", body)
		require.NoError(t, err)
		// Make the request replayable so RoundTrip reads a fresh copy via
		// GetBody and leaves the caller's body in place.
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("Hello, world!")), nil
		}

		origURL := req.URL
		origPath := req.URL.Path

		_, err = cli.Do(req)
		require.NoError(t, err)

		// The original request must still carry its own body value and URL.
		require.Same(t, body, req.Body)
		require.Same(t, origURL, req.URL)
		require.Equal(t, "/test//test/", req.URL.Path)
		require.Equal(t, origPath, req.URL.Path)

		// The original body must still be readable and unchanged.
		data, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, "Hello, world!", string(data))
	})

	// A request whose body cannot be replayed (GetBody is nil) may have its body
	// consumed and closed by RoundTrip, but RoundTrip must not replace the
	// req.Body field on the caller's request.
	t.Run("Non-replayable body field not replaced", func(t *testing.T) {
		body := &idBody{Reader: strings.NewReader("first body")}
		req, err := http.NewRequest(http.MethodPost, "https://example.com/x", body)
		require.NoError(t, err)
		require.Nil(t, req.GetBody)

		_, err = cli.Do(req)
		require.NoError(t, err)

		// The caller's req.Body must be the same value it set; RoundTrip is
		// allowed to consume and close it, but not to replace it.
		require.Same(t, body, req.Body)
	})

	// The outgoing path must reflect what the caller intended. path.Clean must
	// never turn an empty path into "." nor strip a trailing slash.
	t.Run("Path handling", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			url  string
			want string
		}{
			{name: "empty path", url: "https://example.com", want: ""},
			{name: "root path", url: "https://example.com/", want: "/"},
			{name: "trailing slash", url: "https://example.com/test/", want: "/test/"},
			{name: "duplicate slash", url: "https://example.com/test//test", want: "/test/test"},
			{name: "duplicate slash trailing", url: "https://example.com/test//test/", want: "/test/test/"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, tc.url, nil) //nolint:gocritic //nil body is intentional
				require.NoError(t, err)

				gotReq = nil
				_, err = cli.Do(req)
				require.NoError(t, err)
				require.NotNil(t, gotReq)
				require.Equal(t, tc.want, gotReq.URL.Path)
			})
		}
	})
}
