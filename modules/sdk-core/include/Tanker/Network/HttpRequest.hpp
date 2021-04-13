#pragma once

#include <Tanker/Network/HttpMethod.hpp>

#include <string>

namespace Tanker::Network
{
struct HttpRequest
{
  HttpMethod method;
  std::string url;
  std::string authorization;
  std::string instanceId;
  std::string body;
};
}
