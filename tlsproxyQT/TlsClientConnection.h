#pragma once
#include <qobject.h>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QSslSocket>
#include "TlsError.h"

class TlsClientConnection :
    public QObject
{
    Q_OBJECT

public:
    TlsClientConnection(QObject* parent = 0);

    // The accessor methods of the properties
    void setHostName(const QString& hostName);
    QString hostName() const;

    void setPort(const QString& port);
    QString port() const;

    bool sessionActive() const;

    QString cipher() const;

    QString response() const;

    // Returns the controller for the SSL error dialog
    TlsError* sslErrorControl() const;

public Q_SLOTS:
    // This method is called from the UI to create a secure connection
    void secureConnect();

    // This method is called from the UI to send data over the secure connection to the server
    void sendData(const QString& data);

Q_SIGNALS:
    // The change notification signals of the properties
    void hostNameChanged();
    void portChanged();
    void sessionActiveChanged();
    void cipherChanged();
    void responseChanged();

    // This signal is emitted whenever the server reports the certificate chain that should be used
    void certificateChainChanged(const QList<QSslCertificate>& chain);

    // This signal is emitted if the user requested to view the certificate chain
    void viewCertificateChainRequested();

private Q_SLOTS:
    void updateEnabledState();

    // This method is called whenever the state of the SSL socket has changed
    void socketStateChanged(QAbstractSocket::SocketState state);

    // This method is called after an successful SSL-handshake
    void socketEncrypted();

    // This method is called when data arrived from the server via the secured connection
    void socketReadyRead();

    // This method is called when the SSL socket reports SSL-related errors
    void sslErrors(const QList<QSslError>& errors);

    // This method is called if the user wants to ignore SSL-related errors
    void ignoreSslErrors();

private:
    // This methods adds a response from the server to the response property
    void appendString(const QString& line);

    // The SSL socket that does the low-level communication
    QSslSocket* m_socket;

    // The controller for the SSL error dialog
    TlsError* m_sslErrorControl;

    // The property values
    QString m_hostName;
    int m_port;
    bool m_sessionActive;
    QString m_cipher;
    QString m_response;
};

