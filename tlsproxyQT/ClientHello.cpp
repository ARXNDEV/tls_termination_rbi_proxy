#include "ClientHello.h"
#include <QtCore/QString>
#include <cstring>
#include "Extensions.h"

ClientHelloPacket::~ClientHelloPacket()
{
    // Every pointer is null-initialized in the header, so delete[] is safe even
    // for fields that were never allocated.
    delete[] random;
    delete[] session_id;
    delete[] cipher_suites;
    delete[] compress_method;
    delete[] ec_point_formats;
    delete[] signature_alg;
    delete[] supported_groups;
    delete[] supported_points;
}

QString ClientHelloPacket::toString() const
{
    // Qt 6 removed QString::sprintf and never supported Go's %v/%#v verbs.
    return QString::asprintf(
        "TLS record version : 0x%04x\n"
        "Handshake type     : %u\n"
        "Handshake version  : 0x%04x\n"
        "SessionID length   : %u\n"
        "CipherSuites length: %u\n"
        "Extensions length  : %u\n"
        "SNI                : %s\n"
        "ALPN               : %s\n"
        "OCSP               : %s\n",
        static_cast<unsigned>(_message.version),
        static_cast<unsigned>(handshake_type),
        static_cast<unsigned>(handshake_version),
        static_cast<unsigned>(session_id_len),
        static_cast<unsigned>(cipher_suite_len),
        static_cast<unsigned>(extension_len),
        SNI.c_str(),
        ALPNs.c_str(),
        oscp ? "true" : "false");
}

ClientPacketError ClientHelloPacket::Unmarshal(QByteArray packet)
{
    try {
        auto u8 = [](char c) { return static_cast<unsigned char>(c); };

        if (packet.size() < 5)
            return ClientPacketError::ErrHandshakeBadLength;

        // Own a private copy of the raw bytes so _message.raw never dangles
        // (the previous code stored a pointer into a pass-by-value parameter).
        _rawBuf = packet;
        _rawBuf.detach();
        _message.raw = reinterpret_cast<unsigned char*>(_rawBuf.data());

        _message.type = u8(packet.at(0));
        _message.version = static_cast<unsigned short>((u8(packet.at(1)) << 8) | u8(packet.at(2)));
        _message.messageLen = static_cast<unsigned short>((u8(packet.at(3)) << 8) | u8(packet.at(4)));

        if (_message.type != 22) {
            printf("Error: Invalid record type\n");
            return ClientPacketError::ErrHandshakeWrongType;
        }

        QByteArray hs = packet;
        hs.remove(0, 5);

        if (hs.size() < 6) {
            printf("Error: Handshake data length too short\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }

        handshake_type = u8(hs[0]);
        if (handshake_type != 1) {
            printf("Error: Invalid handshake type\n");
            return ClientPacketError::ErrHandshakeWrongType;
        }

        handshake_len = (u8(hs[1]) << 16) | (u8(hs[2]) << 8) | u8(hs[3]);
        handshake_version = static_cast<unsigned short>((u8(hs[4]) << 8) | u8(hs[5]));

        hs.remove(0, 6);

        if (hs.length() < CLIENT_HELLO_RANDOM_NUM_LEN) {
            printf("Error: Handshake data too short for random\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }

        random = new (std::nothrow) unsigned char[CLIENT_HELLO_RANDOM_NUM_LEN]{0};
        if (!random)
            return ClientPacketError::ErrHandshakeExtBadLength;
        std::memcpy(random, hs.data(), CLIENT_HELLO_RANDOM_NUM_LEN);   // was: memcpy(random, hs, ...)
        hs.remove(0, CLIENT_HELLO_RANDOM_NUM_LEN);

        if (hs.length() < 1) {
            printf("Error: Handshake data too short for session ID length\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        session_id_len = u8(hs[0]);
        hs.remove(0, 1);

        if (hs.length() < int(session_id_len)) {
            printf("Error: Handshake data too short for session ID\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        if (session_id_len != 0) {
            session_id = new (std::nothrow) unsigned char[session_id_len]{0};
            if (!session_id)
                return ClientPacketError::ErrHandshakeExtBadLength;
            std::memcpy(session_id, hs.data(), session_id_len);
        }
        hs.remove(0, session_id_len);

        if (hs.length() < 2) {
            printf("Error: Handshake data too short for cipher suite length\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        cipher_suite_len = static_cast<unsigned short>((u8(hs[0]) << 8) | u8(hs[1]));
        const int numCiphers = cipher_suite_len / 2;

        if (hs.length() < 2 + cipher_suite_len) {
            printf("Error: Handshake data too short for cipher suites\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        if (numCiphers > 0) {
            cipher_suites = new (std::nothrow) unsigned char[numCiphers]{0};
            if (!cipher_suites)
                return ClientPacketError::ErrHandshakeExtBadLength;
            for (int i = 0; i < numCiphers; i++)
                cipher_suites[i] = static_cast<unsigned char>((u8(hs[2 + 2 * i]) << 8) | u8(hs[3 + 2 * i]));
        }
        hs.remove(0, 2 + cipher_suite_len);

        if (hs.length() < 1) {
            printf("Error: Handshake data too short for compression methods\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        const int numCompressMethods = u8(hs[0]);
        if (hs.length() < 1 + numCompressMethods) {
            printf("Error: Handshake data too short for compression methods\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        if (numCompressMethods > 0) {
            compress_method = new (std::nothrow) unsigned char[numCompressMethods]{0};
            if (!compress_method)
                return ClientPacketError::ErrHandshakeExtBadLength;
            for (int i = 0; i < numCompressMethods; i++)
                compress_method[i] = u8(hs[1 + i]);
        }
        hs.remove(0, 1 + numCompressMethods);

        if (hs.length() < 2) {
            printf("Error: Handshake data too short for extensions length\n");
            return ClientPacketError::ErrHandshakeBadLength;
        }
        extension_len = static_cast<unsigned short>((u8(hs[0]) << 8) | u8(hs[1]));
        hs.remove(0, 2);
        if (hs.length() < int(extension_len)) {
            printf("Error: Handshake data too short for extensions\n");
            return ClientPacketError::ErrHandshakeExtBadLength;
        }

        while (hs.length() > 0) {
            if (hs.length() < 4) {
                printf("Error: too short for extension header\n");
                return ClientPacketError::ErrHandshakeExtBadLength;
            }
            const short extension_type = static_cast<short>((u8(hs[0]) << 8) | u8(hs[1]));
            const unsigned short length = static_cast<unsigned short>((u8(hs[2]) << 8) | u8(hs[3]));

            if (hs.length() < 4 + length) {
                printf("Error: extension data shorter than its length field\n");
                return ClientPacketError::ErrHandshakeExtBadLength;
            }

            QByteArray data = hs.mid(4, length);
            hs.remove(0, 4 + length);

            switch (static_cast<Extensions>(extension_type)) {
            case Extensions::ExtServerName: {
                if (data.length() < 2) {
                    printf("Error: ServerName extension too short\n");
                    return ClientPacketError::ErrHandshakeExtBadLength;
                }
                // server_name_list length is 2 bytes: data[0]<<8 | data[1]
                // (the original used data[0] twice, corrupting the length).
                const int sniListLen = (u8(data[0]) << 8) | u8(data[1]);
                data.remove(0, 2);
                if (data.length() < sniListLen) {
                    printf("Error: ServerName list data too short\n");
                    return ClientPacketError::ErrHandshakeExtBadLength;
                }
                while (data.length() > 0) {
                    if (data.length() < 3) {
                        printf("Error: ServerName entry too short\n");
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    }
                    const unsigned char nameType = u8(data[0]);
                    const int nameLen = (u8(data[1]) << 8) | u8(data[2]);
                    data.remove(0, 3);
                    if (data.length() < nameLen) {
                        printf("Error: ServerName name data too short\n");
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    }
                    if (nameType == 0)   // host_name
                        SNI = std::string(data.constData(), nameLen);
                    else
                        printf("Unknown ServerName name type: %d\n", nameType);
                    data.remove(0, nameLen);
                }
                break;
            }
            case Extensions::ExtSignatureAlgs: {
                if (data.length() < 2)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                const int sigLen = (u8(data[0]) << 8) | u8(data[1]);
                data.remove(0, 2);
                if (data.length() < sigLen)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                if (sigLen / 2 > 0) {
                    signature_alg = new (std::nothrow) unsigned short[sigLen / 2]{0};
                    if (!signature_alg)
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    for (int i = 0; i < sigLen / 2; i++)
                        signature_alg[i] = static_cast<unsigned short>((u8(data[2 * i]) << 8) | u8(data[2 * i + 1]));
                }
                break;
            }
            case Extensions::ExtSupportedGroups: {
                if (data.length() < 2)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                const int groupLen = (u8(data[0]) << 8) | u8(data[1]);
                data.remove(0, 2);
                if (data.length() < groupLen)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                if (groupLen / 2 > 0) {
                    supported_groups = new (std::nothrow) unsigned short[groupLen / 2]{0};
                    if (!supported_groups)
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    for (int i = 0; i < groupLen / 2; i++)
                        supported_groups[i] = static_cast<unsigned short>((u8(data[2 * i]) << 8) | u8(data[2 * i + 1]));
                }
                break;
            }
            case Extensions::ExtECPointFormats: {
                if (data.length() < 1)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                const int fmtLen = u8(data[0]);
                data.remove(0, 1);
                if (data.length() < fmtLen)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                if (fmtLen > 0) {
                    ec_point_formats = new (std::nothrow) unsigned char[fmtLen]{0};
                    if (!ec_point_formats)
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    std::memcpy(ec_point_formats, data.constData(), fmtLen);
                }
                break;
            }
            case Extensions::ExtStatusRequest:
                oscp = true;
                break;
            case Extensions::ExtALPN: {
                if (data.length() < 2)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                const int alpnLen = (u8(data[0]) << 8) | u8(data[1]);
                data.remove(0, 2);
                if (data.length() < alpnLen)
                    return ClientPacketError::ErrHandshakeExtBadLength;
                while (data.length() > 0) {
                    const unsigned char protoLen = u8(data[0]);
                    if (data.length() < 1 + protoLen)
                        return ClientPacketError::ErrHandshakeExtBadLength;
                    const std::string proto(data.constData() + 1, protoLen);
                    if (!ALPNs.empty()) ALPNs += ",";
                    ALPNs += proto;
                    data.remove(0, 1 + protoLen);
                }
                break;
            }
            default:
                extensions.insert(extension_type, length);
                break;
            }
        }

        return ClientPacketError::ErrHandshakeSuccess;
    }
    catch (const std::bad_alloc& e) {
        printf("Memory allocation failed: %s\n", e.what());
        return ClientPacketError::ErrHandshakeExtBadLength;
    }
    catch (const std::exception& e) {
        printf("Exception caught: %s\n", e.what());
        return ClientPacketError::ErrHandshakeExtBadLength;
    }
}

QString ClientHelloPacket::GetSNI()
{
    return QString::fromStdString(SNI);
}
