#include <Tanker/Init.hpp>
#include <iostream>
#include <unordered_set>
#include <string>

#ifdef TANKER_BUILD_WITH_SSL
#include <openssl/ssl.h>
#ifdef _WIN32
#include <openssl/x509.h>

#include <cryptuiapi.h>
#include <wincrypt.h>
#include <windows.h>
#endif
#endif

#include <sodium.h>

#include <iostream>

namespace Tanker
{
namespace
{
int _init()
{
  if (sodium_init() == -1)
  {
    std::cerr << "failed to initialize sodium" << std::endl;
    std::terminate();
  }
#ifdef TANKER_BUILD_WITH_SSL
  SSL_library_init();
#ifdef _WIN32
  HCERTSTORE hStore;
  PCCERT_CONTEXT pContext = NULL;
  X509* x509 = NULL;
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);

  hStore = CertOpenSystemStoreW(NULL, L"ROOT");

  if (!hStore)
  {
    std::cerr << "Could not open 'ROOT' system store" << std::endl;
    std::terminate();
  }

  std::unordered_set<std::string> certificateSerials;

  while (pContext = CertEnumCertificatesInStore(hStore, pContext))
  {
    char tab[1024];
    tab[CertNameToStrA(1, &pContext->pCertInfo->Issuer, 1, &tab[0], 1024)] = 0;

    char tab2[1024];
    tab2[CertNameToStrA(1, &pContext->pCertInfo->Subject, 1, &tab2[0], 1024)] =
        0;

    std::string subject(tab2);
    std::string issuer(tab);
    std::string serial(pContext->pCertInfo->SerialNumber.pbData,
                       pContext->pCertInfo->SerialNumber.pbData +
                           pContext->pCertInfo->SerialNumber.cbData);

    auto itPair = certificateSerials.emplace(serial + issuer);
    if (!itPair.second)
    {
      std::cout << "Skipping duplicate cerficate: " << subject << std::endl;
      continue;
    }

    x509 = NULL;
    x509 = d2i_X509(NULL,
                    (const unsigned char**)&pContext->pbCertEncoded,
                    pContext->cbCertEncoded);
    if (x509)
    {
      int ok = X509_STORE_add_cert(store, x509);
      if (ok == 0)
      {
        std::cerr << "Failed to add certificate: " << subject << std::endl;
        std::terminate();
      }

      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

#endif
#endif
  return 0;
}
}
void init()
{
  static auto b = _init();
  (void)b;
}
}
