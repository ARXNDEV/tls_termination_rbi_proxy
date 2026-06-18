#pragma once
#include <qobject.h>
#include <QtNetwork/qtcpsocket.h>
#include <QtNetwork/qsslsocket.h>

class ProxyConnection :
    public QObject
{
    Q_OBJECT
public: 
    ProxyConnection(QObject* _parent = NULL);
    QSslSocket _socket;
    void ConnectTo(QString server, int port);
    void ConnectTo(QString server_port);
};

