#ifndef CERTIFICATECACHEHANDLER_H
#define CERTIFICATECACHEHANDLER_H

#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslError>
#include <QtCore/QMap>
#include <QtCore/QList>
#include <QtCore/QMutex>
#include <QtCore/QString>

// Forges per-host leaf certificates signed by the proxy CA and caches them.
// The cert/key caches and the loaded CA are SHARED across all connection
// threads, so every accessor is guarded by a static QMutex.
class CertificateCacheHandler {
public:
    CertificateCacheHandler();

    // Cached forged leaf for serverName (null QSslCertificate if absent).
    QSslCertificate getCachedCertificate(const QString& serverName);

    // Fetch the real upstream cert, verify it, forge a CA-signed leaf for
    // serverName, and cache {leaf cert, leaf key}.
    void cacheCertificate(const QString& serverName, const QString& serverAddr);

    // Private key matching the cached leaf (the reused leaf key). Null if init failed.
    QSslKey getPrivateKey(const QString& serverName);

    // The proxy CA certificate, to be presented to the client below the leaf.
    QList<QSslCertificate> caChain();

    // Real validation against the system trust store + hostname (explicit policy).
    bool validCert(const QSslCertificate& cert,
                   const QList<QSslCertificate>& intermediates,
                   const QString& hostName);

    QString resolveIpAddress(const QString& hostName);
    void printCachedCertificates();

private:
    // Forge a leaf for `sni`, signed by the proxy CA, copying SANs from
    // serverCert when available. Returns the leaf as a QSslCertificate.
    QSslCertificate signCertificate(const QSslCertificate& serverCert, const QString& sni);

    static QMutex                          s_mutex;     // guards the maps below
    static QMap<QString, QSslCertificate>  s_certCache;
    static QMap<QString, QSslKey>          s_keyCache;
};

#endif // CERTIFICATECACHEHANDLER_H
