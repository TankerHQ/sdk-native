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
ConnectionPtr ConnectionFactory::create(std::string url, SdkInfo info)
{
#ifndef EMSCRIPTEN
  return std::make_unique<Connection>(std::move(url), std::move(info));
#else
  return std::make_unique<JsConnection>(url);
#endif
}

ConnectionPtr ConnectionFactory::create(std::string url, std::string context)
{
#ifndef EMSCRIPTEN
  return std::make_unique<Connection>(std::move(url), std::move(context));
#else
  return std::make_unique<JsConnection>(url);
#endif
}
}
}
