package gatesentryproxy

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	// "errors"
	// "fmt"
)

// loadCertificate loads the TLS certificate specified by certFile and keyFile
// into tlsCert.
func loadCertificate() {
	log.Println("[SSL] Loading Certificate")
	if CertFile != "" && KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		if err != nil {
			log.Println("Error loading TLS certificate:", err)
			return
		}
		TLSCert = cert
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("Error parsing X509 certificate:", err)
			return
		}
		ParsedTLSCert = parsed
	}
}

// func loadCertificateWithData(certPEMBlock, keyPEMBlock []byte) error {
//     if len(certPEMBlock) == 0 || len(keyPEMBlock) == 0 {
//         return errors.New("certificate or key PEM blocks are empty")
//     }

//     // Load TLS certificate
//     cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
//     if err != nil {
//         return fmt.Errorf("error loading TLS certificate: %v", err)
//     }
//     TLSCert = cert

//     // Parse X.509 certificate
//     parsed, err := x509.ParseCertificate(cert.Certificate[0])
//     if err != nil {
//         return fmt.Errorf("error parsing X.509 certificate: %v", err)
//     }
//     ParsedTLSCert = parsed

//     // Export certificate to PEM file in current directory
//     exportFilePath := "./exported_certificate.pem"  // Hardcoded path to current directory
//     err = ioutil.WriteFile(exportFilePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw}), 0644)
//     if err != nil {
//         return fmt.Errorf("error exporting certificate to PEM file: %v", err)
//     }

//     return nil
// }


func loadCertificateWithData(certPEMBlock, keyPEMBlock []byte) {

	if len(certPEMBlock) != 0 && len(keyPEMBlock) != 0 {
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			log.Println("Error loading TLS certificate:", err)
			return
		}
		TLSCert = cert
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("Error parsing X509 certificate:", err)
			return
		}
		ParsedTLSCert = parsed
	}
}


// func signCertificate(serverCert *x509.Certificate, selfSigned bool) (cert tls.Certificate, err error) {
// 	log.Println("[SSL] Signing certificate")
// 	h := md5.New()
// 	h.Write(serverCert.Raw)
// 	h.Write([]byte{2})

// 	// Load Google's certificate and private key
// 	googleCertPEM, err := ioutil.ReadFile("google_cert.pem")
// 	if err != nil {
// 		return tls.Certificate{}, err
// 	}
// 	googleKeyPEM, err := ioutil.ReadFile("google_key.pem")
// 	if err != nil {
// 		return tls.Certificate{}, err
// 	}

// 	// Decode PEM blocks
// 	googleCertBlock, _ := pem.Decode(googleCertPEM)
// 	googleKeyBlock, _ := pem.Decode(googleKeyPEM)

// 	// Parse certificate and private key
// 	googleCert, err := x509.ParseCertificate(googleCertBlock.Bytes)
// 	if err != nil {
// 		return tls.Certificate{}, err
// 	}
// 	googlePrivateKey, err := x509.ParsePKCS1PrivateKey(googleKeyBlock.Bytes)
// 	if err != nil {
// 		return tls.Certificate{}, err
// 	}

// 	template := &x509.Certificate{
// 		SerialNumber:                big.NewInt(0).SetBytes(h.Sum(nil)),
// 		Subject:                     serverCert.Subject,
// 		NotBefore:                   serverCert.NotBefore,
// 		NotAfter:                    serverCert.NotAfter,
// 		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
// 		ExtKeyUsage:                 serverCert.ExtKeyUsage,
// 		UnknownExtKeyUsage:          serverCert.UnknownExtKeyUsage,
// 		BasicConstraintsValid:       false,
// 		SubjectKeyId:                nil,
// 		DNSNames:                    serverCert.DNSNames,
// 		PermittedDNSDomainsCritical: serverCert.PermittedDNSDomainsCritical,
// 		PermittedDNSDomains:         serverCert.PermittedDNSDomains,
// 		SignatureAlgorithm:          x509.UnknownSignatureAlgorithm,
// 	}

// 	var newCertBytes []byte
// 	if selfSigned {
// 		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, template, serverCert.PublicKey, googlePrivateKey)
// 	} else {
// 		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, googleCert, serverCert.PublicKey, googlePrivateKey)
// 	}
// 	if err != nil {
// 		return tls.Certificate{}, err
// 	}

// 	newCert := tls.Certificate{
// 		Certificate: [][]byte{newCertBytes},
// 		PrivateKey:  TLSCert.PrivateKey,
// 	}

// 	// Sign the certificate using Google's certificate and private key
// 	// if selfSigned {
// 	// 	newCertBytes, err := x509.CreateCertificate(rand.Reader, template, template, serverCert.PublicKey, googlePrivateKey)
// 	// } else {
// 	// 	newCertBytes, err := x509.CreateCertificate(rand.Reader, template, googleCert, serverCert.PublicKey, googlePrivateKey)
// 	// }
// 	// if err != nil {
// 	//     return tls.Certificate{}, err
// 	// }

// 	// // Create tls.Certificate struct
// 	// newCert := tls.Certificate{
// 	//     Certificate: [][]byte{newCertBytes},
// 	//     PrivateKey:  googlePrivateKey,
// 	// }

// 	if !selfSigned {
// 		newCert.Certificate = append(newCert.Certificate, TLSCert.Certificate...)
// 	}
// 	return newCert, nil
// }

func signCertificate(serverCert *x509.Certificate, selfSigned bool) (cert tls.Certificate, err error) {
	log.Println("[SSL] Signing certificate")
	h := md5.New()
	h.Write(serverCert.Raw)
	h.Write([]byte{2})

	template := &x509.Certificate{
		SerialNumber:                big.NewInt(0).SetBytes(h.Sum(nil)),
		Subject:                     serverCert.Subject,
		NotBefore:                   serverCert.NotBefore,
		NotAfter:                    serverCert.NotAfter,
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:                 serverCert.ExtKeyUsage,
		UnknownExtKeyUsage:          serverCert.UnknownExtKeyUsage,
		BasicConstraintsValid:       false,
		SubjectKeyId:                nil,
		DNSNames:                    serverCert.DNSNames,
		PermittedDNSDomainsCritical: serverCert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         serverCert.PermittedDNSDomains,
		SignatureAlgorithm:          x509.UnknownSignatureAlgorithm,
	}

	// Modern browsers (Chrome/Firefox) ignore the CN and REQUIRE a Subject
	// Alternative Name plus a ServerAuth EKU to accept a leaf for TLS. Guarantee
	// both, even if the upstream/synthetic cert didn't carry them.
	template.IPAddresses = serverCert.IPAddresses
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 && serverCert.Subject.CommonName != "" {
		template.DNSNames = []string{serverCert.Subject.CommonName}
	}
	if len(template.ExtKeyUsage) == 0 {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	var newCertBytes []byte
	if selfSigned {
		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, template, ParsedTLSCert.PublicKey, TLSCert.PrivateKey)
	} else {
		newCertBytes, err = x509.CreateCertificate(rand.Reader, template, ParsedTLSCert, ParsedTLSCert.PublicKey, TLSCert.PrivateKey)
	}
	if err != nil {
		return tls.Certificate{}, err
	}

	newCert := tls.Certificate{
		Certificate: [][]byte{newCertBytes},
		PrivateKey:  TLSCert.PrivateKey,
	}

	if !selfSigned {
		newCert.Certificate = append(newCert.Certificate, TLSCert.Certificate...)
	}
	return newCert, nil
}

func validCert(cert *x509.Certificate, intermediates []*x509.Certificate) bool {
	pool := certPoolWith(intermediates)
	_, err := cert.Verify(x509.VerifyOptions{Intermediates: pool})
	if err == nil {
		return true
	}
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		// There was an error, but not because the certificate wasn't signed
		// by a recognized CA. So we go ahead and use the cert and let
		// the client experience the same error.
		return true
	}

	if ExtraRootCerts != nil {
		_, err = cert.Verify(x509.VerifyOptions{Roots: ExtraRootCerts, Intermediates: pool})
		if err == nil {
			return true
		}
		if _, ok := err.(x509.UnknownAuthorityError); !ok {
			return true
		}
	}

	// Before we give up, we'll try fetching some intermediate certificates.
	if len(cert.IssuingCertificateURL) == 0 {
		return false
	}

	toFetch := cert.IssuingCertificateURL
	fetched := make(map[string]bool)

	for i := 0; i < len(toFetch); i++ {
		certURL := toFetch[i]
		if fetched[certURL] {
			continue
		}
		log.Println("[SSL] Getting certificate from " + certURL)
		resp, err := http.Get(certURL)
		if err == nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		fetchedCert, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// The fetched certificate might be in either DER or PEM format.
		if bytes.Contains(fetchedCert, []byte("-----BEGIN CERTIFICATE-----")) {
			// It's PEM.
			var certDER *pem.Block
			for {
				certDER, fetchedCert = pem.Decode(fetchedCert)
				if certDER == nil {
					break
				}
				if certDER.Type != "CERTIFICATE" {
					continue
				}
				thisCert, err := x509.ParseCertificate(certDER.Bytes)
				if err != nil {
					continue
				}
				pool.AddCert(thisCert)
				toFetch = append(toFetch, thisCert.IssuingCertificateURL...)
			}
		} else {
			// Hopefully it's DER.
			thisCert, err := x509.ParseCertificate(fetchedCert)
			if err != nil {
				continue
			}
			pool.AddCert(thisCert)
			toFetch = append(toFetch, thisCert.IssuingCertificateURL...)
		}
	}

	_, err = cert.Verify(x509.VerifyOptions{Intermediates: pool, Roots: ExtraRootCerts})
	if err == nil {
		return true
	}
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		// There was an error, but not because the certificate wasn't signed
		// by a recognized CA. So we go ahead and use the cert and let
		// the client experience the same error.
		return true
	}
	return false
}

func certPoolWith(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
