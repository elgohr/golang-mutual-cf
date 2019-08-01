package mutual

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/fsnotify/fsnotify"
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

	var cert *tls.Certificate
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}
	tlsConfig.BuildNameToCertificate()

	certPath := os.Getenv(CertLocation)
	keyPath := os.Getenv(KeyLocation)

	watcher, err := watchCertificateUpdates(certPath, keyPath)
	if err != nil {
		return tlsConfig, err
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if ok && event.Op&fsnotify.Write == fsnotify.Write {
					certificate, _ := tls.LoadX509KeyPair(certPath, keyPath)
					cert = &certificate
				}
			}
		}
	}()

	return tlsConfig, nil
}

func watchCertificateUpdates(certPath string, keyPath string) (watcher *fsnotify.Watcher, err error) {
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return
	}

	err = watcher.Add(certPath)
	if err != nil {
		return nil, errors.Wrap(err, "Could not watch " + certPath)
	}
	err = watcher.Add(keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Could not watch " + keyPath)
	}
	return
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
