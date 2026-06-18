#include "ProxyServer.h"
#include "ConnectionHandler.h"

ProxyServer::ProxyServer(QObject* parent) : QTcpServer(parent) {
    
}

bool ProxyServer::Start(quint16 port)
{
    return listen(QHostAddress::Any, port);
}

void ProxyServer::incomingConnection(qintptr socketDescriptor)
{
    ConnectionHandler* handler = new ConnectionHandler(socketDescriptor);
    QThread* thread = new QThread;

    handler->moveToThread(thread);

    connect(thread, &QThread::started, handler, &ConnectionHandler::start);
    connect(handler, &ConnectionHandler::finished, thread, &QThread::quit);
    connect(handler, &ConnectionHandler::finished, handler, &ConnectionHandler::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}

