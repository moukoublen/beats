package aws

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type InputConfig struct {
	Enabled     *bool  `config:"enabled"`
	ServiceName string `config:"service_name"`
	ConfigAWS   `config:",inline"`
}

// IsEnabled returns true if the `enable` field is set to true in the yaml.
func (o *InputConfig) IsEnabled() bool {
	return o != nil && (o.Enabled == nil || *o.Enabled)
}

type SignerTransport struct {
	transport   http.RoundTripper
	credentials aws.CredentialsProvider
	signer      v4.HTTPSigner
	Region      string
	ServiceName string
}

func (st *SignerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	creds, err := st.credentials.Retrieve(req.Context())
	if err != nil {
		return nil, err
	}

	body, err := getRequestBody(req)
	if err != nil {
		return nil, err
	}

	err = st.signer.SignHTTP(
		req.Context(),
		creds,
		req,
		fmt.Sprintf("%x", sha256Hash(body)), // payload hash
		st.ServiceName,
		st.Region,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}

	return st.transport.RoundTrip(req)
}

func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func getRequestBody(req *http.Request) ([]byte, error) {
	// optimize for httpjson requestFactory
	// This is not working rn, TBD
	in := any(req.Body)
	if b, is := in.(*bytes.Buffer); is {
		return b.Bytes(), nil
	}

	// Read and reset the reader to request.
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, errors.Join(err, req.Body.Close())
	}
	if err := req.Body.Close(); err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewBuffer(b))

	return b, nil
}

func NewSignerTransport(innerTransport http.RoundTripper, credentialsProvider aws.CredentialsProvider, region, serviceName string) *SignerTransport {
	return &SignerTransport{
		transport:   innerTransport,
		credentials: credentialsProvider,
		signer:      v4.NewSigner(),
		Region:      region,
		ServiceName: serviceName,
	}
}
