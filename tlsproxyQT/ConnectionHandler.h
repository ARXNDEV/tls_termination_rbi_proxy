#pragma once
#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QSslError>

// One ConnectionHandler drives a single client connection on its own QThread.
// The QSslSocket is created in start() (i.e. in the worker thread) so its
// socket notifiers bind to the right thread and readyRead fires reliably.
class ConnectionHandler : public QObject
{
    Q_OBJECT
public:
    explicit ConnectionHandler(qintptr socketDescriptor, QObject* parent = nullptr);
    ~ConnectionHandler() override;

public slots:
    void start();

signals:
    void finished();

private slots:
    void handleClientReadyRead();
    void handleServerReadyRead();
    void handleClientEncrypted();
    void handleServerEncrypted();
    void handleClientDisconnected();
    void handleServerDisconnected();
    void handleClientSslErrors(const QList<QSslError>& errors);
    void handleServerSslErrors(const QList<QSslError>& errors);

private:
    enum class State { ReadConnect, Bumping, Relaying };

    bool parseConnect();      // returns true once a full CONNECT request is parsed
    void startBump();         // peek ClientHello, mint cert, startServerEncryption
    void pumpClientToServer();
    void pumpServerToClient();
    void shutdown();

    qintptr m_descriptor;
    QSslSocket* clientSocket = nullptr;  // TLS link to the browser (proxy = server)
    QSslSocket* serverSocket = nullptr;  // TLS link to the real upstream

    State m_state = State::ReadConnect;
    QByteArray m_connectBuffer;
    QString m_targetHost;
    quint16 m_targetPort = 443;
    QString m_sni;

    bool m_bumpStarted = false;
    bool m_clientReady = false;
    bool m_serverReady = false;
    bool m_finishedEmitted = false;
};
