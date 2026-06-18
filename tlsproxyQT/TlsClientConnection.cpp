#include "TlsClientConnection.h"

#include <QtNetwork/QSslCipher>

TlsClientConnection::TlsClientConnection(QObject* parent)
    : QObject(parent)
    , m_socket(0)
    , m_sslErrorControl(new TlsError(this))
    , m_hostName("")
    , m_port(443)
    , m_sessionActive(false)
    , m_cipher("<none>")
{
    // User input to the SSL error dialog is forwarded to us via signals
    connect(m_sslErrorControl, SIGNAL(ignoreSslErrors()),
        this, SLOT(ignoreSslErrors()));

    connect(m_sslErrorControl, SIGNAL(viewCertificateChainRequested()),
        this, SIGNAL(viewCertificateChainRequested()));
}

void TlsClientConnection::setHostName(const QString& hostName)
{
    if (m_hostName == hostName)
        return;

    m_hostName = hostName;
    emit hostNameChanged();

    updateEnabledState();
}

QString TlsClientConnection::hostName() const
{
    return m_hostName;
}

void TlsClientConnection::setPort(const QString& portString)
{
    bool ok = false;
    const int port = portString.toInt(&ok);

    if (!ok || (m_port == port))
        return;

    m_port = port;
    emit portChanged();
}

QString TlsClientConnection::port() const
{
    return QString::number(m_port);
}

bool TlsClientConnection::sessionActive() const
{
    return m_sessionActive;
}

QString TlsClientConnection::cipher() const
{
    return m_cipher;
}

QString TlsClientConnection::response() const
{
    return m_response;
}

TlsError* TlsClientConnection::sslErrorControl() const
{
    return m_sslErrorControl;
}

void TlsClientConnection::updateEnabledState()
{
    // Update the sessionActive property depending on the current SSL socket state

    const bool sessionActive = (m_socket && (m_socket->state() == QAbstractSocket::ConnectedState));
    if (m_sessionActive == sessionActive)
        return;

    m_sessionActive = sessionActive;
    emit sessionActiveChanged();
}

void TlsClientConnection::secureConnect()
{
    if (!m_socket) {
        // Create a new SSL socket and connect against its signals to receive notifications about state changes
        m_socket = new QSslSocket(this);
        connect(m_socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
            this, SLOT(socketStateChanged(QAbstractSocket::SocketState)));
        connect(m_socket, SIGNAL(encrypted()),
            this, SLOT(socketEncrypted()));
        connect(m_socket, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(sslErrors(QList<QSslError>)));
        connect(m_socket, SIGNAL(readyRead()),
            this, SLOT(socketReadyRead()));
    }

    // Trigger the SSL-handshake
    m_socket->connectToHostEncrypted(m_hostName, m_port);

    updateEnabledState();
}

void TlsClientConnection::socketStateChanged(QAbstractSocket::SocketState state)
{
    if (m_sslErrorControl->visible())
        return; // We won't react to state changes while the SSL error dialog is visible

    updateEnabledState();

    if (state == QAbstractSocket::UnconnectedState) {
        // If the SSL socket has been disconnected, we delete the socket
        m_cipher = "<none>";
        emit cipherChanged();

        m_socket->deleteLater();
        m_socket = 0;
    }
}

void TlsClientConnection::socketEncrypted()
{
    if (!m_socket)
        return; // Might have disconnected already

    // We started a new connection, so clear the response from previous connections
    m_response.clear();
    emit responseChanged();

    // Retrieve the information about the used cipher and update the property
    const QSslCipher cipher = m_socket->sessionCipher();
    m_cipher = QString("%1, %2 (%3/%4)").arg(cipher.authenticationMethod())
        .arg(cipher.name())
        .arg(cipher.usedBits())
        .arg(cipher.supportedBits());

    emit cipherChanged();

    // Tell the CertificateInfoControl about the certificate chain of this connection
    emit certificateChainChanged(m_socket->peerCertificateChain());
}

void TlsClientConnection::socketReadyRead()
{
    // Read the response from the server and append it to the 'response' property
    appendString(QString::fromUtf8(m_socket->readAll()));
}

void TlsClientConnection::sendData(const QString& input)
{
    if (input.isEmpty())
        return;

    // Add an additional line break, some protocols need that
    appendString(input + '\n');

    // Send the data to the server
   // m_socket->write(input);
    m_socket->write("\r\n");
}

void TlsClientConnection::sslErrors(const QList<QSslError>& errors)
{
    // Assemble the error message, ...
    QStringList messages;
    foreach(const QSslError & error, errors)
        messages << error.errorString();

    // ... make sure the CertificateInfoControl knows about the certificate chain, ...
    emit certificateChainChanged(m_socket->peerCertificateChain());

    // ... and show the SSL error dialog.
    m_sslErrorControl->exec(messages.join("\n"));

    // If the socket has been disconnected (while we have shown the SSL error dialog) we have to update the state
    if (m_socket && (m_socket->state() != QAbstractSocket::ConnectedState))
        socketStateChanged(m_socket->state());
}

void TlsClientConnection::ignoreSslErrors()
{
    if (m_socket)
        m_socket->ignoreSslErrors();
}

void TlsClientConnection::appendString(const QString& line)
{
    // Update the 'response' property
    m_response += line;
    emit responseChanged();
}