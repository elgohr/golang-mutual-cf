package mutual_test

import (
	"github.com/elgohr/golang-mutual-cf"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAddsMutualAuthenticationToRequest(t *testing.T) {
	ts := mutual.Setup(t)
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

	mutual.Clean(t)
}

func TestErrorsWhenAuthorityCouldNotBeFound(t *testing.T) {
	ts := mutual.Setup(t)
	defer ts.Close()

	err := os.Unsetenv("CF_SYSTEM_CERT_PATH")
	if err != nil {
		t.Error(err)
	}

	_, err = mutual.GetClient()
	if err == nil || !strings.HasPrefix(err.Error(), "Could not load CA-Cert:") {
		t.Error(err)
	}

	mutual.Clean(t)
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
	if err := mutual.ConfigureCfEnvironment(tmpDir, caCert); err != nil {
		t.Error(err)
	}

	err = mutual.PrepareCertificate(tmpDir, "CF_SYSTEM_CERT_PATH", "ca.crt", []byte("BROKEN"))
	if err != nil {
		return
	}

	_, err = mutual.GetClient()
	if err == nil || !strings.HasPrefix(err.Error(), "CA-Certificate is invalid:") {
		t.Error(err)
	}

	mutual.Clean(t)
}

