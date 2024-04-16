#pragma once

#include <Tanker/Network/HttpHeaderMap.hpp>

#include <string>

namespace Tanker::Network
{
struct HttpResponse
{
  int statusCode;
  HttpHeaderMap headers;
  std::string body;
};
}
