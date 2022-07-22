#pragma once

#include <Tanker/Network/Backend.hpp>

#include <Tanker/SdkInfo.hpp>

#include <tcurl.hpp>

#include <chrono>

namespace Tanker::Network
{
class CurlBackend : public Backend
{
public:
  CurlBackend(CurlBackend const&) = delete;
  CurlBackend(CurlBackend&&) = delete;
  CurlBackend& operator=(CurlBackend const&) = delete;
  CurlBackend& operator=(CurlBackend&&) = delete;

  CurlBackend(SdkInfo sdkInfo,
              std::chrono::nanoseconds timeout = std::chrono::seconds(30));

  tc::cotask<HttpResponse> fetch(HttpRequest req) override;

private:
  tcurl::read_all_result::header_type _headers;
  tcurl::multi _cl;
  SdkInfo _sdkInfo;
};
}
