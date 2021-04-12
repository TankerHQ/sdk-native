#pragma once

#include <Tanker/Network/HttpVerb.hpp>

#include <string>

namespace Tanker::Network
{
struct HttpRequest
{
  HttpVerb verb;
  std::string url;
  std::string authorization;
  std::string instanceId;
  std::string body;
};
}
