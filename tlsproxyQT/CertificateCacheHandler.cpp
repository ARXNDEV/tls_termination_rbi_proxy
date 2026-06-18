#include "CertificateCacheHandler.h"

#include <QtNetwork/QSslSocket>
#include <QtNetwork/QHostInfo>
#include <QtCore/QDebug>
#include <QtCore/QStringList>

#include <memory>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// ---- shared cache definitions -------------------------------------------------
QMutex                          CertificateCacheHandler::s_mutex;
QMap<QString, QSslCertificate>  CertificateCacheHandler::s_certCache;
QMap<QString, QSslKey>          CertificateCacheHandler::s_keyCache;

// ---- RAII wrappers for OpenSSL handles (free on every path, including errors) -
namespace {
struct X509Del  { void operator()(X509* p) const noexcept { if (p) X509_free(p); } };
struct PKeyDel  { void operator()(EVP_PKEY* p) const noexcept { if (p) EVP_PKEY_free(p); } };
struct BioDel   { void operator()(BIO* p) const noexcept { if (p) BIO_free_all(p); } };
struct BnDel    { void operator()(BIGNUM* p) const noexcept { if (p) BN_free(p); } };
struct ExtDel   { void operator()(X509_EXTENSION* p) const noexcept { if (p) X509_EXTENSION_free(p); } };
using X509Ptr = std::unique_ptr<X509, X509Del>;
using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDel>;
using BioPtr  = std::unique_ptr<BIO, BioDel>;
using BnPtr   = std::unique_ptr<BIGNUM, BnDel>;
using ExtPtr  = std::unique_ptr<X509_EXTENSION, ExtDel>;

QByteArray pemFromBio(BIO* bio)
{
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    return (mem && mem->data) ? QByteArray(mem->data, static_cast<int>(mem->length)) : QByteArray();
}

// Proxy CA + the single reused leaf key, loaded/generated once.
QMutex          g_initMutex;
bool            g_initDone = false;
bool            g_initOk   = false;
X509Ptr         g_caCert{nullptr};
PKeyPtr         g_caKey{nullptr};
PKeyPtr         g_leafKey{nullptr};     // ONE key reused for every forged leaf
QSslCertificate g_caQt;
QSslKey         g_leafQtKey;

bool ensureInit()
{
    QMutexLocker lock(&g_initMutex);
    if (g_initDone)
        return g_initOk;
    g_initDone = true;

    // CA cert/key paths: env-overridable. Defaults assume PEM files next to the
    // binary. (See "How to test" for generating these.)
    const QByteArray caCertPath = qEnvironmentVariable("PROXY_CA_CERT", "proxy-ca.crt").toUtf8();
    const QByteArray caKeyPath  = qEnvironmentVariable("PROXY_CA_KEY",  "proxy-ca.key").toUtf8();

    BioPtr certBio(BIO_new_file(caCertPath.constData(), "r"));
    if (!certBio) { qCritical() << "[CA] cannot open CA cert:" << caCertPath; return false; }
    g_caCert.reset(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
    if (!g_caCert) { qCritical() << "[CA] cannot parse CA cert"; ERR_print_errors_fp(stderr); return false; }

    BioPtr keyBio(BIO_new_file(caKeyPath.constData(), "r"));
    if (!keyBio) { qCritical() << "[CA] cannot open CA key:" << caKeyPath; return false; }
    g_caKey.reset(PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr));
    if (!g_caKey) { qCritical() << "[CA] cannot parse CA key"; ERR_print_errors_fp(stderr); return false; }

    // One RSA-2048 leaf key for all forged certs (OpenSSL 3 API; not blocking
    // per-request like the deprecated RSA_generate_key path).
    g_leafKey.reset(EVP_RSA_gen(2048));
    if (!g_leafKey) { qCritical() << "[CA] leaf key generation failed"; ERR_print_errors_fp(stderr); return false; }

    BioPtr caPem(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(caPem.get(), g_caCert.get());
    g_caQt = QSslCertificate(pemFromBio(caPem.get()), QSsl::Pem);

    BioPtr leafPem(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(leafPem.get(), g_leafKey.get(), nullptr, nullptr, 0, nullptr, nullptr);
    g_leafQtKey = QSslKey(pemFromBio(leafPem.get()), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);

    g_initOk = !g_caQt.isNull() && !g_leafQtKey.isNull();
    if (g_initOk) qInfo() << "[CA] loaded proxy CA and generated reusable leaf key";
    return g_initOk;
}
} // namespace

CertificateCacheHandler::CertificateCacheHandler() = default;

QSslCertificate CertificateCacheHandler::getCachedCertificate(const QString& serverName)
{
    QMutexLocker lock(&s_mutex);
    return s_certCache.value(serverName);   // null QSslCertificate if absent
}

QSslKey CertificateCacheHandler::getPrivateKey(const QString& serverName)
{
    {
        QMutexLocker lock(&s_mutex);
        if (s_keyCache.contains(serverName))
            return s_keyCache.value(serverName);
    }
    // Every leaf shares the one reused key, so fall back to it.
    return ensureInit() ? g_leafQtKey : QSslKey();
}

QList<QSslCertificate> CertificateCacheHandler::caChain()
{
    if (!ensureInit())
        return {};
    return { g_caQt };
}

void CertificateCacheHandler::cacheCertificate(const QString& serverName, const QString& serverAddr)
{
    if (!ensureInit()) {
        qCritical() << "[SSL] CA not available; cannot forge certificate";
        return;
    }

    qInfo() << "[SSL] forging certificate for" << serverName << "via" << serverAddr;

    // Fetch the real upstream certificate chain (VerifyNone here only so we can
    // obtain the chain; we then verify it ourselves against the trust store).
    QSslSocket sock;
    sock.setPeerVerifyMode(QSslSocket::VerifyNone);
    sock.connectToHostEncrypted(serverAddr.isEmpty() ? serverName : serverAddr, 443, serverName);

    QSslCertificate real;            // may stay null if upstream is unreachable
    if (sock.waitForEncrypted(15000)) {
        const QList<QSslCertificate> chain = sock.peerCertificateChain();
        sock.disconnectFromHost();
        if (!chain.isEmpty()) {
            real = chain.first();
            if (!validCert(real, chain.mid(1), serverName)) {
                qWarning() << "[SSL] upstream certificate INVALID for" << serverName
                           << "- refusing to forge a trusted cert (no MITM of bad servers)";
                return;   // explicit policy: do not bump an untrusted upstream
            }
        }
    } else {
        qWarning() << "[SSL] could not reach upstream" << serverName << ":" << sock.errorString()
                   << "- forging from SNI only";
    }

    const QSslCertificate leaf = signCertificate(real, serverName);
    if (leaf.isNull()) {
        qWarning() << "[SSL] failed to forge leaf for" << serverName;
        return;
    }

    QMutexLocker lock(&s_mutex);
    s_certCache.insert(serverName, leaf);
    s_keyCache.insert(serverName, g_leafQtKey);   // the reused leaf key
    qInfo() << "[SSL] cached forged certificate for" << serverName;
}

bool CertificateCacheHandler::validCert(const QSslCertificate& cert,
                                        const QList<QSslCertificate>& intermediates,
                                        const QString& hostName)
{
    // Real validation: verify the presented chain against the system trust
    // store AND check the hostname. (The old code read sslErrors() on a socket
    // that never handshook, so it always returned true.)
    QList<QSslCertificate> chain;
    chain << cert << intermediates;
    const QList<QSslError> errors = QSslCertificate::verify(chain, hostName);
    if (!errors.isEmpty()) {
        for (const QSslError& e : errors)
            qWarning() << "[SSL] upstream verify error:" << e.errorString();
        return false;
    }
    return true;
}

QSslCertificate CertificateCacheHandler::signCertificate(const QSslCertificate& serverCert, const QString& sni)
{
    if (!ensureInit())
        return {};

    X509Ptr leaf(X509_new());
    if (!leaf)
        return {};

    // Parse the real server cert from a NAMED DER buffer so the pointer handed
    // to d2i_X509 stays alive while it is read (the old code passed
    // serverCert.toDer().data() from a destroyed temporary -> dangling).
    X509Ptr serverX509;
    if (!serverCert.isNull()) {
        const QByteArray der = serverCert.toDer();
        const unsigned char* p = reinterpret_cast<const unsigned char*>(der.constData());
        serverX509.reset(d2i_X509(nullptr, &p, der.size()));
    }

    X509_set_version(leaf.get(), 2);   // v3

    // Unique random serial (required when one CA signs many leaves).
    {
        unsigned char serialBytes[16];
        RAND_bytes(serialBytes, sizeof(serialBytes));
        serialBytes[0] &= 0x7F;        // ensure positive
        BnPtr bn(BN_bin2bn(serialBytes, sizeof(serialBytes), nullptr));
        if (bn)
            BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(leaf.get()));
    }

    // Subject: copy from the real cert when available, else CN = SNI.
    if (serverX509) {
        X509_set_subject_name(leaf.get(), X509_get_subject_name(serverX509.get()));
    } else {
        X509_NAME* nm = X509_get_subject_name(leaf.get());
        const QByteArray cn = sni.toUtf8();
        X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn.constData()), -1, -1, 0);
    }

    // Issuer = the proxy CA's subject -> the leaf chains to the CA.
    // (The old code set issuer = subject in BOTH branches, making it self-signed.)
    X509_set_issuer_name(leaf.get(), X509_get_subject_name(g_caCert.get()));

    // Validity: now-1h .. now+397d.
    X509_gmtime_adj(X509_getm_notBefore(leaf.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(leaf.get()), 60L * 60 * 24 * 397);

    // Public key = the reused leaf key (its private half is returned/cached so a
    // TLS handshake with the client is actually possible).
    X509_set_pubkey(leaf.get(), g_leafKey.get());

    // Build SAN: copy DNS names from the real cert, always include the SNI.
    QStringList dnsNames;
    if (!serverCert.isNull()) {
        const auto alt = serverCert.subjectAlternativeNames();
        for (auto it = alt.constBegin(); it != alt.constEnd(); ++it)
            if (it.key() == QSsl::DnsEntry && !dnsNames.contains(it.value()))
                dnsNames << it.value();
    }
    if (!sni.isEmpty() && !dnsNames.contains(sni))
        dnsNames << sni;
    if (dnsNames.isEmpty())
        dnsNames << sni;

    QStringList sanParts;
    for (const QString& d : dnsNames)
        sanParts << ("DNS:" + d);
    const QByteArray sanValue = sanParts.join(QLatin1Char(',')).toUtf8();

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, g_caCert.get(), leaf.get(), nullptr, nullptr, 0);

    if (ExtPtr san{ X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name,
                                        const_cast<char*>(sanValue.constData())) })
        X509_add_ext(leaf.get(), san.get(), -1);
    if (ExtPtr bc{ X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
                                       const_cast<char*>("critical,CA:FALSE")) })
        X509_add_ext(leaf.get(), bc.get(), -1);
    if (ExtPtr eku{ X509V3_EXT_conf_nid(nullptr, &ctx, NID_ext_key_usage,
                                        const_cast<char*>("serverAuth")) })
        X509_add_ext(leaf.get(), eku.get(), -1);

    // Sign with the CA private key.
    if (!X509_sign(leaf.get(), g_caKey.get(), EVP_sha256())) {
        qWarning() << "[SSL] X509_sign failed";
        ERR_print_errors_fp(stderr);
        return {};
    }

    BioPtr out(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(out.get(), leaf.get());
    return QSslCertificate(pemFromBio(out.get()), QSsl::Pem);
    // All OpenSSL handles freed here by RAII on every path.
}

void CertificateCacheHandler::printCachedCertificates()
{
    QMutexLocker lock(&s_mutex);
    qDebug() << "Cached forged certificates:" << s_certCache.size();
    for (auto it = s_certCache.constBegin(); it != s_certCache.constEnd(); ++it) {
        qDebug() << " " << it.key()
                 << "subject:" << it.value().subjectInfo(QSslCertificate::CommonName)
                 << "issuer:"  << it.value().issuerInfo(QSslCertificate::CommonName)
                 << "expires:" << it.value().expiryDate().toString(Qt::ISODate);
    }
}

QString CertificateCacheHandler::resolveIpAddress(const QString& hostName)
{
    const QHostInfo info = QHostInfo::fromName(hostName);
    if (info.error() == QHostInfo::NoError && !info.addresses().isEmpty())
        return info.addresses().first().toString();
    return QString();
}
