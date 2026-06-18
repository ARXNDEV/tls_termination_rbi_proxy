#pragma once

#include <string>
#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QString>

// From IETF (TLS ClientHello):
// struct {
//     ProtocolVersion client_version;
//     Random random;
//     SessionID session_id;
//     CipherSuite cipher_suites<2..2^16-2>;
//     CompressionMethod compression_methods<1..2^8-1>;
//     Extension extensions<0..2^16-1>;
// } ClientHello;

typedef struct _TLSMessage {
    unsigned char* raw = nullptr;     // points into ClientHelloPacket::_rawBuf (owned)
    unsigned char  type = 0;
    unsigned short version = 0;
    unsigned short messageLen = 0;
} TLSMessage;

#define CLIENT_HELLO_RANDOM_NUM_LEN 32

enum class ClientPacketError {
    ErrHandshakeSuccess = 0,
    ErrHandshakeWrongType = 1,
    ErrHandshakeBadLength = 2,
    ErrHandshakeExtBadLength = 3,
};

class ClientHelloPacket {

    QByteArray _rawBuf;               // owns the raw packet bytes that _message.raw points into
    TLSMessage _message;
    unsigned char  handshake_type = 0;
    unsigned int   handshake_len = 0;
    unsigned int   handshake_version = 0;
    unsigned char* random = nullptr;
    unsigned int   session_id_len = 0;
    unsigned char* session_id = nullptr;
    unsigned short cipher_suite_len = 0;
    unsigned char* cipher_suites = nullptr;
    unsigned char* compress_method = nullptr;
    unsigned short extension_len = 0;
    unsigned char* ec_point_formats = nullptr;
    std::string SNI;
    unsigned short* signature_alg = nullptr;
    unsigned short* supported_groups = nullptr;
    unsigned char*  supported_points = nullptr;
    bool oscp = false;
    std::string ALPNs;

    QMap<int, int> extensions;

public:
    ClientHelloPacket() = default;
    ~ClientHelloPacket();

    // Non-copyable: it owns raw new[] buffers (avoids double-free).
    ClientHelloPacket(const ClientHelloPacket&) = delete;
    ClientHelloPacket& operator=(const ClientHelloPacket&) = delete;

    QString toString() const;
    ClientPacketError Unmarshal(QByteArray data);
    QString GetSNI();
};
