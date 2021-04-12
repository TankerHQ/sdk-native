#pragma once

#include <Tanker/Network/HttpRequest.hpp>
#include <Tanker/Network/HttpResponse.hpp>
#include <Tanker/SdkInfo.hpp>

#include <fetchpp/client.hpp>
#include <fetchpp/http/url.hpp>

#include <tconcurrent/coroutine.hpp>

#include <chrono>

namespace Tanker::Network
{
class FetchppBackend
{
public:
  FetchppBackend(FetchppBackend const&) = delete;
  FetchppBackend(FetchppBackend&&) = delete;
  FetchppBackend& operator=(FetchppBackend const&) = delete;
  FetchppBackend& operator=(FetchppBackend&&) = delete;

  FetchppBackend(SdkInfo sdkInfo,
                 std::chrono::nanoseconds timeout = std::chrono::seconds(30));
  ~FetchppBackend();

  tc::cotask<HttpResponse> fetch(HttpRequest req);

private:
  fetchpp::client _cl;
  SdkInfo _sdkInfo;
};
}
