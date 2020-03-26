package mutual

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	CertLocation = "CF_INSTANCE_CERT"
	KeyLocation  = "CF_INSTANCE_KEY"
	CaLocation   = "CF_SYSTEM_CERT_PATH"
)

func GetClient() (client *http.Client, err error) {
	client = http.DefaultClient
	config, err := addCertificateConfig()
	if err != nil {
		return client, err
	}
	client.Transport = &http.Transport{
		TLSClientConfig: config,
	}
	return client, nil
}

func addCertificateConfig() (config *tls.Config, err error) {
	caCertPool, err := getCaCert()
	if err != nil {
		return nil, err
	}

	certPath := os.Getenv(CertLocation)
	keyPath := os.Getenv(KeyLocation)

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
			return &cert, nil
		},
	}

	return tlsConfig, nil
}

func getCaCert() (caCertPool *x509.CertPool, err error) {
	caCert, err := ioutil.ReadFile(os.Getenv(CaLocation))
	if err != nil {
		return nil, errors.Wrap(err, "Could not load CA-Cert")
	}
	pcaCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, errors.Wrap(err, "CA-Certificate is invalid")
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AddCert(pcaCert)
	return caCertPool, nil
}
