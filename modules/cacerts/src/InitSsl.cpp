#include <Tanker/Cacerts/InitSsl.hpp>

#include <Tanker/Log/Log.hpp>

#ifdef _WIN32
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <wincrypt.h>
#include <windows.h>

#include <set>
#include <vector>
#endif

TLOG_CATEGORY("InitSsl");

extern const uint8_t embedded_cacerts_data[];
extern const uint32_t embedded_cacerts_size;

namespace Tanker
{
namespace Cacerts
{
namespace net = boost::asio;

void init()
{
  static auto b = [] {
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init();       /* initialize library */
    return 0;
  }();
  (void)b;
}

namespace
{
auto get_certificate_authority()
{
#if TANKER_EMBED_CERTIFICATES
  return net::buffer(embedded_cacerts_data, embedded_cacerts_size);
#elif defined(_WIN32)
  std::vector<uint8_t> certs;
  auto buffer = net::dynamic_buffer(certs);
  std::set<std::basic_string<BYTE>> excludes;

  auto hStore = CertOpenSystemStore(NULL, "ROOT");
  if (!hStore)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "Cannot open system certificate store");

  PCCERT_CONTEXT pContext = NULL;
  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL)
  {

    auto serial =
        std::basic_string<BYTE>(pContext->pCertInfo->SerialNumber.pbData,
                                pContext->pCertInfo->SerialNumber.cbData);
    auto res = excludes.insert(serial);
    if (!res.second)
    {
      TINFO("Certificate SerialNumber already encountered, skipping");
      continue;
    }

    DWORD size = 0;
    // This is how we calculate the size of the buffer to write to.
    if (!CryptBinaryToStringA(pContext->pbCertEncoded,
                              pContext->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER,
                              nullptr,
                              &size))
    {
      TINFO("Can not get encoded ssl certificate size");
      continue;
    }
    if (!CryptBinaryToStringA(pContext->pbCertEncoded,
                              pContext->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER,
                              static_cast<LPSTR>(buffer.prepare(size).data()),
                              &size))
    {
      TINFO("Can not encode ssl certificate");
      continue;
    }
    buffer.commit(size);
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);
  return certs;
#endif
}
}

net::ssl::context create_ssl_context()
{
  using net::ssl::context;

  auto ctx = context{context::tls_client};
  auto auth = get_certificate_authority();

  ctx.set_options(context::no_sslv3 | context::no_tlsv1 | context::no_tlsv1_1 |
                  context::single_dh_use);

  ctx.set_verify_mode(net::ssl::verify_peer |
                      net::ssl::verify_fail_if_no_peer_cert);

  ctx.add_certificate_authority(net::const_buffer(auth.data(), auth.size()));
  return ctx;
}

net::ssl::context& get_ssl_context()
{
  static auto context = create_ssl_context();
  return context;
}
}
}
