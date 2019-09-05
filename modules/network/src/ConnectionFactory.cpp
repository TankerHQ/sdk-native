#include <Tanker/Network/ConnectionFactory.hpp>

#ifndef EMSCRIPTEN
#include <Tanker/Network/Connection.hpp>
#else
#include <Tanker/Network/JsConnection.hpp>
#endif

namespace Tanker
{
namespace Network
{
ConnectionPtr ConnectionFactory::create(std::string url,
                                        nonstd::optional<SdkInfo> info)
{
#ifndef EMSCRIPTEN
  return std::make_unique<Connection>(std::move(url), std::move(info));
#else
  return std::make_unique<JsConnection>(url);
#endif
}
}
}
