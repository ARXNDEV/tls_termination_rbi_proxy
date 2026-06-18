package gatesentryproxy

import (
	"crypto/tls"
)

func createSelfSignedTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{TLSCert},
	}, nil
}
