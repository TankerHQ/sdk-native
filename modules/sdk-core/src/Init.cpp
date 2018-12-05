#include <Tanker/Init.hpp>

#ifdef TANKER_BUILD_WITH_SSL
#include <openssl/ssl.h>
#endif

namespace Tanker
{
void init()
{
#ifdef TANKER_BUILD_WITH_SSL
  SSL_library_init();
#endif
}
}
