#include "ProxyConnection.h"
#include <QtNetwork/qsslcertificateextension.h>
ProxyConnection::ProxyConnection(QObject* parent) : QObject(parent), _socket(nullptr) {
	
}

void ProxyConnection::ConnectTo(QString server, int port)
{
	_socket.connectToHostEncrypted(server, port);
	if (!_socket.waitForConnected(5000)) {
		//Error
	}
	
	QSslCertificate certificate = _socket.peerCertificate();
	QList<QSslCertificateExtension> extensions = certificate.extensions();
	QByteArray serialNumber = certificate.serialNumber();
	QDateTime effectiveDate = certificate.effectiveDate();
	QDateTime expiryDate = certificate.expiryDate();
	QMultiMap<QSsl::AlternativeNameEntryType, QString> sni = certificate.subjectAlternativeNames();
	QByteArray version = certificate.version();
//	QByteArrayList list = certificate.subjectInfoAttributes();
	QStringList commonName  = certificate.subjectInfo(QSslCertificate::CommonName);
	QStringList country = certificate.subjectInfo(QSslCertificate::CountryName);
	QStringList emailaddress = certificate.subjectInfo(QSslCertificate::EmailAddress);
	QStringList locality = certificate.subjectInfo(QSslCertificate::LocalityName);
	QStringList organization = certificate.subjectInfo(QSslCertificate::Organization);
	QStringList state = certificate.subjectInfo(QSslCertificate::StateOrProvinceName);
	//QStringList state = certificate.subjectInfo(QSslCertificate::);
	//QStringList state = certificate.subjectInfo(QSslCertificate::StateOrProvinceName);

	//for(int i = 0; i < list.length(); i++)
	//{
	//	QByteArray s = list.at(i);
	//}
}
