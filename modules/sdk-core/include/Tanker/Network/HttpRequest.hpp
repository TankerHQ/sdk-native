#pragma once

#include <Tanker/Network/HttpHeaderMap.hpp>
#include <Tanker/Network/HttpMethod.hpp>

#include <string>

namespace Tanker::Network
{
struct HttpRequest
{
  HttpMethod method;
  HttpHeaderMap headers;
  std::string url;
  std::string body;
};
}
