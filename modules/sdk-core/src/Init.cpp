#include <Tanker/Init.hpp>

#include <Tanker/Crypto/Init.hpp>

#include <boost/asio/ssl/context.hpp>

namespace Tanker
{
namespace
{
void initSsl()
{
  static auto b = [] {
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init();       /* initialize library */
    return 0;
  }();
  (void)b;
}
}

void init()
{
  Crypto::init();
  // Even without fetchpp, we need LibreSSL for sqlcipher
  initSsl();
}
}
