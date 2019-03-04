#include <Tanker/Init.hpp>
#include <iostream>

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

  if (!hStore) {
    std::cerr << "Could not open 'ROOT' system store" << std::endl;
    std::terminate();
  }


  while (pContext = CertEnumCertificatesInStore(hStore, pContext))
  {
    x509 = NULL;
    x509 = d2i_X509(NULL,
                    (const unsigned char**)&pContext->pbCertEncoded,
                    pContext->cbCertEncoded);
    if (x509)
    {
      int ok = X509_STORE_add_cert(store, x509);
      if (ok == 0) {
        std::cerr << "Failed to add certificate" << std::endl;
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
