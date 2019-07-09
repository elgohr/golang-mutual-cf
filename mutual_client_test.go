package mutual_test

import (
	"crypto/tls"
	"github.com/elgohr/golang-mutual-cf"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	CaFileName   = "ca.crt"
	CertFileName = "cert.crt"
	KeyFileName  = "key"
)

func TestAddsMutualAuthenticationToRequest(t *testing.T) {
	ts, _ := setup(t)
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
	ts, _ := setup(t)
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
	ts, tmpDir := setup(t)
	defer ts.Close()

	err := prepareCertificate(tmpDir, mutual.CaLocation, CaFileName, []byte("BROKEN"))
	if err != nil {
		return
	}

	_, err = mutual.GetClient()
	if err == nil || !strings.HasPrefix(err.Error(), "CA-Certificate is invalid:") {
		t.Error(err)
	}

	clean(t)
}

func TestUpdatesTheGlobalCertificateWhenPrivateKeyChanges(t *testing.T) {
	ts, tmpDir := setup(t)
	defer ts.Close()

	client, _ := mutual.GetClient()

	tlsConfig := client.Transport.(*http.Transport).TLSClientConfig
	oldCert, _ := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})

	other, err := ioutil.ReadFile("testdata/other")
	if err != nil {
		t.Error(err)
	}
	err = prepareCertificate(tmpDir, mutual.KeyLocation, KeyFileName, other)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1 * time.Second)

	newCert, _ := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if oldCert == newCert {
		t.Error("Certificate should have changed, but didn't")
	}

	clean(t)
}

func TestErrorsWhenPrivateKeyCouldNotBeWatched(t *testing.T) {
	ts, tmpDir := setup(t)
	defer ts.Close()

	join := filepath.Join(tmpDir, KeyFileName)
	if err := os.Remove(join); err != nil {
		t.Error(err)
	}
	client, err := mutual.GetClient()
	if err == nil || !strings.Contains(err.Error(), "The system cannot find the file specified") {
		t.Error(err)
	}
	if client == nil {
		t.Error("Should return the client regardless of it's updating or not")
	}

	clean(t)
}

func TestErrorsWhenPublicKeyCouldNotBeWatched(t *testing.T) {
	ts, tmpDir := setup(t)
	defer ts.Close()

	join := filepath.Join(tmpDir, CertFileName)
	if err := os.Remove(join); err != nil {
		t.Error(err)
	}
	client, err := mutual.GetClient()
	if err == nil || !strings.Contains(err.Error(), "The system cannot find the file specified") {
		t.Error(err)
	}
	if client == nil {
		t.Error("Should return the client regardless of it's updating or not")
	}

	clean(t)
}

func TestUpdatesTheGlobalCertificateWhenPublicKeyChanges(t *testing.T) {
	ts, tmpDir := setup(t)
	defer ts.Close()

	client, _ := mutual.GetClient()

	tlsConfig := client.Transport.(*http.Transport).TLSClientConfig
	oldCert, _ := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})

	other, err := ioutil.ReadFile("testdata/other.pub")
	if err != nil {
		t.Error(err)
	}
	err = prepareCertificate(tmpDir, mutual.CertLocation, CertFileName, other)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1 * time.Second)

	newCert, _ := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if oldCert == newCert {
		t.Error("Certificate should have changed, but didn't")
	}

	clean(t)
}

func setup(t *testing.T) (ts *httptest.Server, tmpDir string) {
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	caCert := ts.TLS.Certificates[0].Certificate[0]

	var err error
	tmpDir, err = ioutil.TempDir("", "golang-mutual")
	if err != nil {
		t.Error(err)
	}
	if err := configureCfEnvironment(tmpDir, caCert); err != nil {
		t.Error(err)
	}
	return ts, tmpDir
}

func clean(t *testing.T) {
	err := os.Unsetenv(mutual.CertLocation)
	if err != nil {
		t.Error(err)
	}
	err = os.Unsetenv(mutual.KeyLocation)
	if err != nil {
		t.Error(err)
	}
	err = os.Unsetenv(mutual.CaLocation)
	if err != nil {
		t.Error(err)
	}
}

func configureCfEnvironment(tmpDir string, rootCA []byte) (err error) {
	err = prepareCertificate(tmpDir, mutual.CaLocation, CaFileName, rootCA)
	if err != nil {
		return
	}
	localhostPub, err := ioutil.ReadFile("testdata/localhost.pub")
	if err != nil {
		return
	}
	err = prepareCertificate(tmpDir, mutual.CertLocation, CertFileName, localhostPub)
	if err != nil {
		return
	}
	localhost, err := ioutil.ReadFile("testdata/localhost")
	if err != nil {
		return
	}
	err = prepareCertificate(tmpDir, mutual.KeyLocation, KeyFileName, localhost)
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

