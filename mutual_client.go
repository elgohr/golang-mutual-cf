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
	certLocation = "CF_INSTANCE_CERT"
	keyLocation  = "CF_INSTANCE_KEY"
	caLocation   = "CF_SYSTEM_CERT_PATH"
)

var (
	cert *tls.Certificate
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
	caCert, err := ioutil.ReadFile(os.Getenv(caLocation))
	if err != nil {
		return nil, errors.Wrap(err, "Could not load CA-Cert")
	}
	pcaCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, errors.Wrap(err, "CA-Certificate is invalid")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(pcaCert)
	updateCertificate()

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

func updateCertificate() {
	certificate, _ := tls.LoadX509KeyPair(os.Getenv(certLocation), os.Getenv(keyLocation))
	cert = &certificate
}
