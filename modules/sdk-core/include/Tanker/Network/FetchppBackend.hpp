#pragma once

#include <Tanker/Network/Backend.hpp>

#include <Tanker/SdkInfo.hpp>

#include <fetchpp/client.hpp>
#include <fetchpp/http/url.hpp>

#include <chrono>

namespace Tanker::Network
{
class FetchppBackend : public Backend
{
public:
  FetchppBackend(FetchppBackend const&) = delete;
  FetchppBackend(FetchppBackend&&) = delete;
  FetchppBackend& operator=(FetchppBackend const&) = delete;
  FetchppBackend& operator=(FetchppBackend&&) = delete;

  FetchppBackend(SdkInfo sdkInfo,
                 std::chrono::nanoseconds timeout = std::chrono::seconds(30));
  ~FetchppBackend();

  tc::cotask<HttpResponse> fetch(HttpRequest req) override;

private:
  std::shared_ptr<fetchpp::client> _cl;
  SdkInfo _sdkInfo;
};
}
