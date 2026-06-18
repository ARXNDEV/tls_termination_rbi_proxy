#include "ConnectionHandler.h"

#include <QtCore/QRegularExpression>
#include <QtCore/QDebug>

#include "ClientHelloHandler.h"
#include "ClientHello.h"
#include "ProxyException.h"
#include "CertificateCacheHandler.h"

namespace {
constexpr int kHandshakeTimeoutMs = 15000;
}

ConnectionHandler::ConnectionHandler(qintptr socketDescriptor, QObject* parent)
    : QObject(parent), m_descriptor(socketDescriptor)
{
    // NOTE: do NOT create the socket here. This ctor runs in the server thread;
    // the socket must be created/initialized in the worker thread (start()) so
    // its event notifiers bind correctly and readyRead fires.
}

ConnectionHandler::~ConnectionHandler() = default;  // sockets are QObject children

void ConnectionHandler::start()
{
    clientSocket = new QSslSocket(this);
    serverSocket = new QSslSocket(this);

    if (!clientSocket->setSocketDescriptor(m_descriptor)) {
        qWarning() << "[bump] invalid client socket descriptor:" << clientSocket->errorString();
        shutdown();
        return;
    }

    connect(clientSocket, &QSslSocket::readyRead,    this, &ConnectionHandler::handleClientReadyRead);
    connect(clientSocket, &QSslSocket::disconnected, this, &ConnectionHandler::handleClientDisconnected);
    connect(clientSocket, &QSslSocket::encrypted,    this, &ConnectionHandler::handleClientEncrypted);
    connect(clientSocket, &QSslSocket::sslErrors,    this, &ConnectionHandler::handleClientSslErrors);

    connect(serverSocket, &QSslSocket::readyRead,    this, &ConnectionHandler::handleServerReadyRead);
    connect(serverSocket, &QSslSocket::disconnected, this, &ConnectionHandler::handleServerDisconnected);
    connect(serverSocket, &QSslSocket::encrypted,    this, &ConnectionHandler::handleServerEncrypted);
    connect(serverSocket, &QSslSocket::sslErrors,    this, &ConnectionHandler::handleServerSslErrors);

    // Data may already be buffered if CONNECT arrived before signals were wired.
    if (clientSocket->bytesAvailable() > 0)
        handleClientReadyRead();
}

void ConnectionHandler::handleClientReadyRead()
{
    switch (m_state) {
    case State::ReadConnect:
        if (parseConnect()) {
            m_state = State::Bumping;
            // The ClientHello may already be buffered (pipelined). Try to bump.
            if (clientSocket->bytesAvailable() > 0)
                startBump();
        }
        break;

    case State::Bumping:
        if (!m_bumpStarted)
            startBump();
        // While the handshake is in progress QSslSocket consumes records
        // internally; nothing to do here until encrypted() fires.
        break;

    case State::Relaying:
        pumpClientToServer();
        break;
    }
}

bool ConnectionHandler::parseConnect()
{
    m_connectBuffer.append(clientSocket->readAll());
    if (!m_connectBuffer.contains("\r\n\r\n"))
        return false;  // wait for the full request line + headers

    static const QRegularExpression re(QStringLiteral("CONNECT\\s+([^:\\s]+):(\\d+)"));
    const QRegularExpressionMatch m = re.match(QString::fromLatin1(m_connectBuffer));
    if (!m.hasMatch()) {
        qWarning() << "[bump] not a CONNECT request; closing";
        shutdown();
        return false;
    }

    m_targetHost = m.captured(1);
    m_targetPort = static_cast<quint16>(m.captured(2).toUInt());
    qInfo() << "[bump] CONNECT" << m_targetHost << ":" << m_targetPort;

    // Tell the client the tunnel is up (plaintext, before TLS begins).
    clientSocket->write("HTTP/1.1 200 Connection Established\r\n\r\n");
    clientSocket->flush();

    // Connect to the REAL upstream and verify its certificate (explicit policy:
    // VerifyPeer + hostname check; sslErrors are logged and NOT ignored, so an
    // untrusted/invalid upstream aborts the handshake instead of being relayed).
    serverSocket->setPeerVerifyMode(QSslSocket::VerifyPeer);
    serverSocket->setProtocol(QSsl::SecureProtocols);
    serverSocket->connectToHostEncrypted(m_targetHost, m_targetPort, m_targetHost);
    return true;
}

void ConnectionHandler::startBump()
{
    m_bumpStarted = true;
    try {
        // PEEK (do not consume) the ClientHello: parse the SNI for the forged
        // cert, while leaving the bytes in the socket buffer so OpenSSL receives
        // the ClientHello when we call startServerEncryption().
        ClientHelloHandler helloHandler;
        const QByteArray hello = helloHandler.HandleClientHello(clientSocket);

        m_sni.clear();
        ClientHelloPacket packet;
        if (packet.Unmarshal(hello) == ClientPacketError::ErrHandshakeSuccess)
            m_sni = packet.GetSNI();
        if (m_sni.isEmpty())
            m_sni = m_targetHost;  // fall back to the CONNECT host
        qInfo() << "[bump] SNI =" << m_sni;

        // Get (or forge+cache) a leaf cert for the SNI signed by the proxy CA,
        // plus its private key. The cache is shared across all worker threads.
        CertificateCacheHandler certs;
        QSslCertificate leaf = certs.getCachedCertificate(m_sni);
        if (leaf.isNull()) {
            certs.cacheCertificate(m_sni, m_targetHost);
            leaf = certs.getCachedCertificate(m_sni);
        }
        const QSslKey leafKey = certs.getPrivateKey(m_sni);

        if (leaf.isNull() || leafKey.isNull()) {
            qWarning() << "[bump] could not obtain forged cert/key for" << m_sni;
            shutdown();
            return;
        }

        // Present {leaf, CA} chain + leaf key, then complete the client-side TLS
        // handshake. The peeked-but-unconsumed ClientHello drives it.
        QList<QSslCertificate> chain;
        chain << leaf << certs.caChain();
        clientSocket->setLocalCertificateChain(chain);
        clientSocket->setPrivateKey(leafKey);
        clientSocket->setProtocol(QSsl::SecureProtocols);
        clientSocket->setPeerVerifyMode(QSslSocket::VerifyNone);  // we don't ask the browser for a client cert
        clientSocket->startServerEncryption();
    }
    catch (const ProxyException&) {
        qWarning() << "[bump] failed to read/parse ClientHello";
        shutdown();
    }
    catch (const QException&) {
        qWarning() << "[bump] unexpected exception during bump";
        shutdown();
    }
}

void ConnectionHandler::handleClientEncrypted()
{
    qInfo() << "[bump] client TLS established for" << m_sni;
    m_clientReady = true;
    m_state = State::Relaying;
    // Flush anything already buffered in either direction.
    pumpClientToServer();
    pumpServerToClient();
}

void ConnectionHandler::handleServerEncrypted()
{
    qInfo() << "[bump] upstream TLS established for" << m_targetHost;
    m_serverReady = true;
    pumpServerToClient();
    pumpClientToServer();
}

void ConnectionHandler::handleServerReadyRead()
{
    pumpServerToClient();
}

// Decrypted client plaintext -> upstream. QSslSocket buffers writes made before
// its own handshake completes and flushes them once it is encrypted, so this is
// safe to call as soon as the client side is ready.
void ConnectionHandler::pumpClientToServer()
{
    if (!m_clientReady || !serverSocket)
        return;
    const QByteArray data = clientSocket->readAll();
    if (!data.isEmpty())
        serverSocket->write(data);
}

// Decrypted upstream plaintext -> client. Requires the client side to be
// encrypted (so the write is encrypted to the browser).
void ConnectionHandler::pumpServerToClient()
{
    if (!m_serverReady || !m_clientReady || !clientSocket)
        return;
    const QByteArray data = serverSocket->readAll();
    if (!data.isEmpty())
        clientSocket->write(data);
}

void ConnectionHandler::handleClientDisconnected() { shutdown(); }
void ConnectionHandler::handleServerDisconnected() { shutdown(); }

void ConnectionHandler::handleClientSslErrors(const QList<QSslError>& errors)
{
    for (const QSslError& e : errors)
        qWarning() << "[bump] client-side SSL error:" << e.errorString();
    // Not ignored: a failure here means the browser rejected our forged cert
    // (CA not installed) -> let the handshake fail.
}

void ConnectionHandler::handleServerSslErrors(const QList<QSslError>& errors)
{
    for (const QSslError& e : errors)
        qWarning() << "[bump] UPSTREAM SSL error (refusing to relay):" << e.errorString();
    // Deliberately NOT calling ignoreSslErrors(): the real server's certificate
    // must validate before we relay. Invalid upstream -> handshake aborts.
}

void ConnectionHandler::shutdown()
{
    if (m_finishedEmitted)
        return;
    m_finishedEmitted = true;
    if (clientSocket) clientSocket->disconnectFromHost();
    if (serverSocket) serverSocket->disconnectFromHost();
    emit finished();
}
