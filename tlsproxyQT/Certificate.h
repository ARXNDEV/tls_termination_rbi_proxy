#pragma once
#include <QtNetwork/qsslcertificate.h>
class Certificate
{
public: 
	QSslCertificate SignCertificate(QSslCertificate cert);
	void LoadCertificates(); 
	void LoadCertificateWithData(); 
	bool IsCertificateValid(QSslCertificate cert);
};

