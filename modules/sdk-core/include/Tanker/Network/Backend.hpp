#pragma once

#include <Tanker/Network/HttpRequest.hpp>
#include <Tanker/Network/HttpResponse.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Network
{
class Backend
{
public:
  virtual ~Backend() = default;

  virtual tc::cotask<HttpResponse> fetch(HttpRequest req) = 0;
  virtual tc::cotask<void> stop() = 0;
};
}
