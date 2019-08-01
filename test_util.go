package mutual

import (
"io/ioutil"
"net/http"
"net/http/httptest"
"os"
"path/filepath"
"testing"
)

func Setup(t *testing.T) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	caCert := ts.TLS.Certificates[0].Certificate[0]

	tmpDir, err := ioutil.TempDir("", "golang-mutual")
	if err != nil {
		t.Error(err)
	}
	if err := ConfigureCfEnvironment(tmpDir, caCert); err != nil {
		t.Error(err)
	}
	return ts
}

func Clean(t *testing.T) {
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

func ConfigureCfEnvironment(tmpDir string, rootCA []byte) (err error) {
	err = PrepareCertificate(tmpDir, "CF_SYSTEM_CERT_PATH", "ca.crt", rootCA)
	if err != nil {
		return
	}
	localhostPub, err := ioutil.ReadFile("testdata/localhost.pub")
	if err != nil {
		return
	}
	err = PrepareCertificate(tmpDir, "CF_INSTANCE_CERT", "cert.crt", localhostPub)
	if err != nil {
		return
	}
	localhost, err := ioutil.ReadFile("testdata/localhost")
	if err != nil {
		return
	}
	err = PrepareCertificate(tmpDir, "CF_INSTANCE_KEY", "key.key", localhost)
	return
}

func PrepareCertificate(tmpDir string, envKey string, filename string, certContent []byte) error {
	file := filepath.Join(tmpDir, filename)
	err := ioutil.WriteFile(file, certContent, os.ModePerm)
	if err != nil {
		return err
	}
	return os.Setenv(envKey, file)
}

