#pragma once

namespace Tanker
{
namespace Config
{
constexpr bool hasSSL()
{
#ifdef TANKER_BUILD_WITH_SSL
  return true;
#else
  return false;
#endif
}
}
}
