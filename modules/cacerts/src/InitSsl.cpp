#include <Tanker/Cacerts/InitSsl.hpp>

#include <Tanker/Log/Log.hpp>

#if TANKER_BUILD_WITH_SSL
#include <openssl/ssl.h>
#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#endif
#endif

TLOG_CATEGORY("InitSsl");

extern const char embedded_cacerts_data[];
extern unsigned embedded_cacerts_size;

namespace Tanker
{
namespace Cacerts
{
void init()
{
#if TANKER_BUILD_WITH_SSL
  SSL_library_init();
#endif
}

void add_certificate_authority(void* vctx)
{
#if TANKER_BUILD_WITH_SSL
#if TANKER_EMBED_CERTIFICATES
  auto ctx = static_cast<SSL_CTX*>(vctx);

  BIO* bio = BIO_new_mem_buf(const_cast<char*>(embedded_cacerts_data),
                             embedded_cacerts_size);
  if (!bio)
  {
    TERROR("can't open BIO with cert data");
    std::terminate();
  }

  STACK_OF(X509_INFO)* inf =
      PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
  if (!inf)
  {
    TERROR("can't read PEM info");
    std::terminate();
  }

  for (int i = 0; i < sk_X509_INFO_num(inf); i++)
  {
    X509_INFO* itmp = sk_X509_INFO_value(inf, i);
    if (itmp->x509)
    {
      if (!X509_STORE_add_cert(ctx->cert_store, itmp->x509))
      {
        TERROR("can't add X509 certs");
        std::terminate();
      }
    }
  }

  sk_X509_INFO_pop_free(inf, X509_INFO_free);
  ::BIO_free(bio);
#elif defined(_WIN32)
  auto ctx = static_cast<SSL_CTX*>(vctx);
  HCERTSTORE hStore;
  PCCERT_CONTEXT pContext = NULL;
  X509* x509;
  X509_STORE* store = ctx->cert_store;

  hStore = CertOpenSystemStore(NULL, "ROOT");

  if (!hStore)
  {
    TERROR("can't open system store");
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
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);
#endif
#endif
}
}
}
