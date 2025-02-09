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
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/stretchr/testify/require"
)

type RoundTripperFunc func(req *http.Request) (*http.Response, error)

// RoundTrip implements the RoundTripper interface.
func (rt RoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

// trackingProvider wraps a credentials.Provider and tracks how many times Retrieve() is called.
// This helps us determine that after Expire() a refresh (via Get) is triggered.
type trackingProvider struct {
	provider credentials.Provider
	count    int
}

func (tp *trackingProvider) Retrieve() (credentials.Value, error) {
	tp.count++
	return tp.provider.Retrieve()
}

func (tp *trackingProvider) IsExpired() bool {
	return tp.provider.IsExpired()
}

func TestSigV4_Inferred_Region(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "secret")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "token")
	os.Setenv("AWS_REGION", "us-west-2")

	sess, err := session.NewSession(&aws.Config{
		// Setting to an empty string to demostrate the default value from the yaml
		// won't override the environment's region.
		Region: aws.String(""),
	})
	require.NoError(t, err)
	_, err = sess.Config.Credentials.Get()
	require.NoError(t, err)

	require.NotNil(t, sess.Config.Region)
	require.Equal(t, "us-west-2", *sess.Config.Region)
}

func TestSigV4RoundTripper(t *testing.T) {
	var gotReq *http.Request

	rt := &sigV4RoundTripper{
		region: "us-east-2",
		next: RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{StatusCode: http.StatusOK}, nil
		}),
		signer: signer.NewSigner(credentials.NewStaticCredentials(
			"test-id",
			"secret",
			"token",
		)),
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

		require.Equal(t, origReq.Header.Get("Authorization"), gotReq.Header.Get("Authorization"))
	})

	t.Run("Escape URL", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "https://example.com/test//test", strings.NewReader("Hello, world!"))
		require.NoError(t, err)
		require.Equal(t, "/test//test", req.URL.Path)

		_, err = cli.Do(req)
		require.NoError(t, err)
		require.NotNil(t, gotReq)

		require.Equal(t, "/test/test", gotReq.URL.Path)
	})

	t.Run("No body", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/test/test", nil)
		require.NoError(t, err)
		_, err = cli.Do(req)
		require.NoError(t, err)
	})

	t.Run("Expired Token", func(t *testing.T) {
		t.Run("Successful retry", func(t *testing.T) {
			// Setup tracking credentials to verify that after Expire()
			// a refresh is triggered by observing an extra call to Retrieve().
			// Note: The first signing call will trigger a Retrieve() so we expect count >= 2.
			// For example, if count == 1 then no refresh happened after Expire().
			tp := &trackingProvider{provider: &credentials.StaticProvider{
				Value: credentials.Value{
					AccessKeyID:     "test-id",
					SecretAccessKey: "secret",
					SessionToken:    "token",
				},
			}}
			trackingCreds := credentials.NewCredentials(tp)
			rt.signer.Credentials = trackingCreds

			callCount := 0
			originalNext := rt.next
			defer func() { rt.next = originalNext }()

			rt.next = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				callCount++
				if callCount == 1 {
					return &http.Response{
						StatusCode: http.StatusForbidden,
						Header: http.Header{
							"X-Amzn-Errortype": []string{"ExpiredTokenException"},
						},
					}, nil
				}
				return &http.Response{StatusCode: http.StatusOK}, nil
			})

			req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("Hello, world!"))
			require.NoError(t, err)

			resp, err := cli.Do(req)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Greater(t, tp.count, 1, "Expected credentials retrieval to be triggered at least twice (initial retrieval and after Expire())")
		})

		t.Run("Different 403 error does not retry", func(t *testing.T) {
			callCount := 0
			originalNext := rt.next
			defer func() { rt.next = originalNext }()

			rt.next = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				callCount++
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Header: http.Header{
						"X-Amzn-Errortype": []string{"SomeOtherError"},
					},
				}, nil
			})

			req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("Hello, world!"))
			require.NoError(t, err)

			resp, err := cli.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)

			require.Equal(t, 1, callCount, "Expected only one HTTP call")
		})
	})
}
