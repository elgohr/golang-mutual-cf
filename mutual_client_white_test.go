package mutual

import (
"crypto/tls"
"net/http"
"os"
"testing"
)

func TestUsesTheGlobalCertificate(t *testing.T) {
	ts := Setup(t)
	defer ts.Close()

	client, _ := GetClient()

	certificate, _ := tls.LoadX509KeyPair(os.Getenv(certLocation), os.Getenv(keyLocation))
	cert = &certificate
	givenCert, _ := client.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if givenCert != &certificate {
		t.Error("Expected global certificate to be used")
	}

	Clean(t)
}
