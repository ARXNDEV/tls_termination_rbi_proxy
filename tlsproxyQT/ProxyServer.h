#pragma once
#include <QtCore/qobject.h>
#include <QtCore/QDebug>
#include <QtCore/QThread>
#include <QtCore/QString>
#include <QtCore/QEventLoop>
#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qtcpsocket.h>

#define MAX_BUFFER_SIZE 10000


class ProxyServer :
    public QTcpServer
{
    Q_OBJECT
public:
    explicit ProxyServer(QObject* parent = nullptr);

    bool Start(quint16 port);

protected:
    void incomingConnection(qintptr socketDescriptor) override;
};

