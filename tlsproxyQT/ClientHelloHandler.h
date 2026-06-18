#pragma once
#include <QtNetwork/qsslsocket.h>

class ClientHelloHandler
{
public: 
	QByteArray HandleClientHello(QTcpSocket* socket);
};

