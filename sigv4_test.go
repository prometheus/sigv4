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

func TestSigV4_Inferred_Region(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "secret")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "token")
	os.Setenv("AWS_REGION", "us-west-2")
	ctx := context.TODO()
	awscfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(""),
	)

	require.NoError(t, err)
	_, err = awscfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)

	require.NotNil(t, awscfg.Region)
	require.Equal(t, "us-west-2", awscfg.Region)
}

func TestSigV4RoundTripper(t *testing.T) {
	var gotReq *http.Request

	awscfg, _ := config.LoadDefaultConfig(
		ctx,
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
}
