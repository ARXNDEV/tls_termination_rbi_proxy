#include "Certificate.h"

QSslCertificate Certificate::SignCertificate(QSslCertificate cert)
{
//	QCryptographicHash h(QCryptographicHash::Algorithm::Md5);
//	h.addData(cert.toText().toUtf8());
//	//h.addData(QByteArray(2));
////			h.Write([]byte{ 2 })
//
//	QSslCertificate cert2;
//	//cert2
//	template : = &x509.Certificate{
//				SerialNumber:                big.NewInt(0).SetBytes(h.Sum(nil)),
//				Subject : serverCert.Subject,
//				NotBefore : serverCert.NotBefore,
//				NotAfter : serverCert.NotAfter,
//				KeyUsage : x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
//				ExtKeyUsage : serverCert.ExtKeyUsage,
//				UnknownExtKeyUsage : serverCert.UnknownExtKeyUsage,
//				BasicConstraintsValid : false,
//				SubjectKeyId : nil,
//				DNSNames : serverCert.DNSNames,
//				PermittedDNSDomainsCritical : serverCert.PermittedDNSDomainsCritical,
//				PermittedDNSDomains : serverCert.PermittedDNSDomains,
//				SignatureAlgorithm : x509.UnknownSignatureAlgorithm,
//		}
//
//		var newCertBytes[]byte
//			if selfSigned{
//				newCertBytes, err = x509.CreateCertificate(rand.Reader, template, template, ParsedTLSCert.PublicKey, TLSCert.PrivateKey)
//			}
//			else {
//				newCertBytes, err = x509.CreateCertificate(rand.Reader, template, ParsedTLSCert, ParsedTLSCert.PublicKey, TLSCert.PrivateKey)
//			}
//		if err != nil{
//			return tls.Certificate{}, err
//		}
//
//		newCert: = tls.Certificate{
//			Certificate: [] [] byte{newCertBytes},
//			PrivateKey : TLSCert.PrivateKey,
//		}
//
//		if !selfSigned{
//			newCert.Certificate = append(newCert.Certificate, TLSCert.Certificate...)
//		}
//			return newCert, nil
//	}

	return QSslCertificate();
}

void Certificate::LoadCertificates()
{
}

void Certificate::LoadCertificateWithData()
{
}

bool Certificate::IsCertificateValid(QSslCertificate cert)
{
	return false;
}
