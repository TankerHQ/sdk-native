#include <Tanker/Init.hpp>

#include <Tanker/Crypto/Init.hpp>

#if TANKER_WITH_FETCHPP
#include <boost/asio/ssl/context.hpp>
#endif

namespace Tanker
{
namespace
{
void initSsl()
{
#if TANKER_WITH_FETCHPP
  static auto b = [] {
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init();       /* initialize library */
    return 0;
  }();
  (void)b;
#endif
}
}

void init()
{
  Crypto::init();
  initSsl();
}
}
