package mutual_test

import (
	"github.com/elgohr/golang-mutual-cf"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddsMutualAuthenticationToRequest(t *testing.T) {
	ts := setup(t)
	defer ts.Close()

	client, err := mutual.GetClient()
	if err != nil {
		t.Error(err)
	}

	res, err := client.Get(ts.URL)
	defer res.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("Responded with %v", res.StatusCode)
	}

	clean(t)
}

func TestErrorsWhenAuthorityCouldNotBeFound(t *testing.T) {
	ts := setup(t)
	defer ts.Close()

	err := os.Unsetenv("CF_SYSTEM_CERT_PATH")
	if err != nil {
		t.Error(err)
	}

	_, err = mutual.GetClient()
	if err == nil || !strings.HasPrefix(err.Error(), "Could not load CA-Cert:") {
		t.Error(err)
	}

	clean(t)
}

func TestErrorsWhenAuthorityIsInvalid(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	caCert := ts.TLS.Certificates[0].Certificate[0]

	tmpDir, err := ioutil.TempDir("", "golang-mutual")
	if err != nil {
		t.Error(err)
	}
	if err := configureCfEnvironment(tmpDir, caCert); err != nil {
		t.Error(err)
	}

	err = prepareCertificate(tmpDir, "CF_SYSTEM_CERT_PATH", "ca.crt", []byte("BROKEN"))
	if err != nil {
		return
	}

	_, err = mutual.GetClient()
	if err == nil || !strings.HasPrefix(err.Error(), "CA-Certificate is invalid:") {
		t.Error(err)
	}

	clean(t)
}

func setup(t *testing.T) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	caCert := ts.TLS.Certificates[0].Certificate[0]

	tmpDir, err := ioutil.TempDir("", "golang-mutual")
	if err != nil {
		t.Error(err)
	}
	if err := configureCfEnvironment(tmpDir, caCert); err != nil {
		t.Error(err)
	}
	return ts
}

func configureCfEnvironment(tmpDir string, rootCA []byte) (err error) {
	err = prepareCertificate(tmpDir, "CF_SYSTEM_CERT_PATH", "ca.crt", rootCA)
	if err != nil {
		return
	}
	err = prepareCertificate(tmpDir, "CF_INSTANCE_CERT", "cert.crt", LocalhostCert)
	if err != nil {
		return
	}
	err = prepareCertificate(tmpDir, "CF_INSTANCE_KEY", "key.key", LocalhostKey)
	if err != nil {
		return
	}
	return
}

func prepareCertificate(tmpDir string, envKey string, filename string, certContent []byte) error {
	file := filepath.Join(tmpDir, filename)
	err := ioutil.WriteFile(file, certContent, os.ModePerm)
	if err != nil {
		return err
	}
	return os.Setenv(envKey, file)
}

func clean(t *testing.T) {
	err := os.Unsetenv("CF_INSTANCE_CERT")
	if err != nil {
		t.Error(err)
	}
	err = os.Unsetenv("CF_INSTANCE_KEY")
	if err != nil {
		t.Error(err)
	}
	err = os.Unsetenv("CF_SYSTEM_CERT_PATH")
	if err != nil {
		t.Error(err)
	}
}

// taken from https://github.com/golang/go/blob/master/src/net/http/internal/testcert.go
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)
