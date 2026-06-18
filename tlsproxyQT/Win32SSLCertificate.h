#pragma once
#include "Certificate.h"
class Win32SSLCertificate: Certificate
{
public: 
	QSslCertificate SignCertificate(QSslCertificate cert);
	
};

