#pragma once

#include <string>

namespace Tanker::Network
{
struct HttpResponse
{
  int statusCode;
  std::string contentType;
  std::string body;
};
}
