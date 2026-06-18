#include <QtCore/QCoreApplication>
#include "ProxyServer.h"
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    ProxyServer server;
    if (!server.Start(8080)) {
        qFatal("Failed to start server");
        return 1;
    }
    
    return a.exec();
}
