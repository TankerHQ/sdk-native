#include <Tanker/Crypto/Init.hpp>

#include <sodium.h>

#include <iostream>
#include <string>

namespace Tanker
{
namespace Crypto
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
  return 0;
}
}

void init()
{
  static auto b = _init();
  (void)b;
}
}
}
