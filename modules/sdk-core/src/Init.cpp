#include <Tanker/Init.hpp>
#include <iostream>
#include <string>
#include <unordered_set>

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
