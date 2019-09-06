#include <Tanker/Init.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Init.hpp>

namespace Tanker
{
void init()
{
  Cacerts::init();
  Crypto::init();
}
}
