#include <Tanker/Init.hpp>

#ifdef TANKER_BUILD_WITH_SSL
#include <openssl/ssl.h>
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
