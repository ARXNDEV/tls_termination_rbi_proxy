#pragma once
enum class Extensions
{
	ExtServerName = 0,
	ExtMaxFragLen = 1,
	ExtClientCertURL = 2,
	ExtTrustedCAKeys = 3,
	ExtTruncatedHMAC = 4,
	ExtStatusRequest = 5,
	ExtUserMapping = 6,
	ExtClientAuthz = 7,
	ExtServerAuthz = 8,
	ExtCertType = 9,
	ExtSupportedGroups = 10,
	ExtECPointFormats = 11,
	ExtSRP = 12,
	ExtSignatureAlgs = 13,
	ExtUseSRTP = 14,
	ExtHeartbeat = 15,
	ExtALPN = 16,// Replaced NPN
	ExtStatusRequestV2 = 17,
	ExtSignedCertTS = 18, // Certificate Transparency
	ExtClientCertType = 19,
	ExtServerCertType = 20,
	ExtPadding = 21,// Temp http://www.iana.org/go/draft-ietf-tls-padding
	ExtEncryptThenMAC = 22,
	ExtExtendedMasterSecret = 23,
	ExtSessionTicket = 35,
	ExtNPN = 13172, // Next Protocol Negotiation not ratified and replaced by ALPN
	ExtRenegotiationInfo = 65281

	//std::string toString() {}
	//func(e Extension) String() string {
	//	if name, ok : = ExtensionReg[e]; ok{
	//		return name
	//	}
	//		return fmt.Sprintf("%#v (unknown)", e)
	//}

	//// TLS Extensions http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
	//

	//	var ExtensionReg = map[Extension]string{
	//		ExtServerName:           "server_name",
	//		ExtMaxFragLen : "max_fragment_length",
	//		ExtClientCertURL : "client_certificate_url",
	//		ExtTrustedCAKeys : "trusted_ca_keys",
	//		ExtTruncatedHMAC : "truncated_hmac",
	//		ExtStatusRequest : "status_request",
	//		ExtUserMapping : "user_mapping",
	//		ExtClientAuthz : "client_authz",
	//		ExtServerAuthz : "server_authz",
	//		ExtCertType : "cert_type",
	//		ExtSupportedGroups : "supported_groups",
	//		ExtECPointFormats : "ec_point_formats",
	//		ExtSRP : "srp",
	//		ExtSignatureAlgs : "signature_algorithms",
	//		ExtUseSRTP : "use_srtp",
	//		ExtHeartbeat : "heartbeat",
	//		ExtALPN : "application_layer_protocol_negotiation",
	//		ExtStatusRequestV2 : "status_request_v2",
	//		ExtSignedCertTS : "signed_certificate_timestamp",
	//		ExtClientCertType : "client_certificate_type",
	//		ExtServerCertType : "server_certificate_type",
	//		ExtPadding : "padding",
	//		ExtEncryptThenMAC : "encrypt_then_mac",
	//		ExtExtendedMasterSecret : "extended_master_secret",
	//		ExtSessionTicket : "SessionTicket TLS",
	//		ExtNPN : "next_protocol_negotiation",
	//		ExtRenegotiationInfo : "renegotiation_info",
	//}
};

