#include "ClientHelloHandler.h"
#include "ProxyException.h"

// Reads the client's first TLS record (5-byte header + handshake body) and
// returns it WITHOUT consuming it (peek), so the bytes remain available for the
// QSslSocket TLS engine when startServerEncryption() is later called.
//
// Fixes:
//  * length bytes are cast to unsigned char before shifting (a byte >= 0x80 was
//    being sign-extended and corrupting the length);
//  * short reads are handled (peek/waitForReadyRead until the whole record is
//    buffered) before indexing.
QByteArray ClientHelloHandler::HandleClientHello(QTcpSocket* connection)
{
    constexpr int kTimeoutMs = 15000;
    auto u8 = [](char c) { return static_cast<unsigned char>(c); };

    if (!connection)
        throw ProxyException();

    // 1) Ensure the 5-byte TLS record header is buffered, then peek it.
    while (connection->bytesAvailable() < 5) {
        if (!connection->waitForReadyRead(kTimeoutMs))
            throw ProxyException();
    }
    const QByteArray header = connection->peek(5);

    if (u8(header.at(0)) != 22) {                  // 22 = handshake; 0x80 => SSLv2
        throw ProxyException();
    }
    if (u8(header.at(1)) != 3) {                   // TLS major version must be 3
        throw ProxyException();
    }

    const int recordLen = (u8(header.at(3)) << 8) | u8(header.at(4));
    if (recordLen < 4 || recordLen > 0x4000) {     // 16 KiB max TLS record
        throw ProxyException();
    }

    // 2) Ensure the full record (header + body) is buffered, then peek it whole.
    const int total = 5 + recordLen;
    while (connection->bytesAvailable() < total) {
        if (!connection->waitForReadyRead(kTimeoutMs))
            throw ProxyException();
    }
    const QByteArray record = connection->peek(total);   // NOTE: peek, not read
    if (record.size() < total)
        throw ProxyException();

    // 3) Sanity-check the handshake header (type 1 = ClientHello, length match).
    if (u8(record.at(5)) != 1)
        throw ProxyException();
    const int handshakeLen = (u8(record.at(6)) << 16) | (u8(record.at(7)) << 8) | u8(record.at(8));
    if (handshakeLen != recordLen - 4) {
        printf("Error: handshake length %d != expected %d\n", handshakeLen, recordLen - 4);
        throw ProxyException();
    }

    printf("ClientHello peeked successfully (%d bytes).\n", total);
    return record;   // full record, still buffered in the socket for the TLS engine
}
