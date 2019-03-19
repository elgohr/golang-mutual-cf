package mutual

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
)

func GetMutualClient() (*http.Client, error) {
	caPath := os.Getenv("CF_SYSTEM_CERT_PATH")
	certPath := os.Getenv("CF_INSTANCE_CERT")
	keyPath := os.Getenv("CF_INSTANCE_KEY")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pcaCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(pcaCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
