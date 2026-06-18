// #include "Win32SSLCertificate.h"

// #include <Windows.h>
// #include <wincrypt.h>
// #include <bcrypt.h>
// #include <wincrypt.h>
// #include <certenroll.h>
// #include <atlbase.h>
// #include <comdef.h>
// #pragma comment(lib, "Crypt32.lib")
// #pragma comment(lib, "Bcrypt.lib")

// QSslCertificate Win32SSLCertificate::SignCertificate(QSslCertificate cert)
// {
//   /*  HRESULT hr = S_OK;
//     CComPtr<IX509Enrollment> pEnrollment = nullptr;
//     CComPtr<IX509CertificateRequestCertificate> pRequest = nullptr;
//     CComPtr<IX509PrivateKey> pPrivateKey = nullptr;
//     CComPtr<ICspInformations> pCspInformations = nullptr;
//     CComPtr<IX509ExtensionKeyUsage> pKeyUsage = nullptr;
//     CComPtr<IObjectId> pObjectId = nullptr;
//     BSTR bstrRequest = nullptr;
//   //  BSTR bstrTemplateName = SysAllocString(templateName);
//     // Create a private key
//     hr = CoCreateInstance(__uuidof(CX509PrivateKey), NULL, CLSCTX_INPROC_SERVER, __uuidof(IX509PrivateKey), (void**)&pPrivateKey);
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to create private key instance." << std::endl;
//         goto Cleanup;
//     }

//     hr = pPrivateKey->put_AlgorithmName(SysAllocString(L"RSA"));
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to set algorithm name." << std::endl;
//         goto Cleanup;
//     }

//     hr = pPrivateKey->put_Length(2048);
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to set key length." << std::endl;
//         goto Cleanup;
//     }

//     hr = pPrivateKey->Create();
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to create private key." << std::endl;
//         goto Cleanup;
//     }

//     // Create a certificate request
//     hr = CoCreateInstance(__uuidof(CX509CertificateRequestCertificate), NULL, CLSCTX_INPROC_SERVER, __uuidof(IX509CertificateRequestCertificate), (void**)&pRequest);
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to create certificate request instance." << std::endl;
//         goto Cleanup;
//     }

//     hr = pRequest->InitializeFromPrivateKey(XCN_CERT, pPrivateKey, NULL);
//     if (FAILED(hr))
//     {
//         std::cerr << "Failed to initialize certificate request." << std::endl;
//         goto Cleanup;
//     }

//     */
//     return QSslCertificate();
// }
