#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Network/Backend.hpp>
#include <Tanker/Network/HttpMethod.hpp>
#include <Tanker/Network/HttpRequest.hpp>
#include <Tanker/Network/HttpResponse.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <boost/outcome/result.hpp>

#include <nlohmann/json_fwd.hpp>

#include <tconcurrent/coroutine.hpp>

#include <chrono>
#include <string_view>

namespace Tanker::Network
{
struct HttpError
{
  HttpMethod method;
  std::string href;
  int status;
  Errors::AppdErrc ec;
  std::string message;
  std::string traceId;
};
}

namespace Tanker::Network
{
void from_json(nlohmann::json const& j, HttpError& e);

std::error_code make_error_code(HttpError const& e);
[[noreturn]] void outcome_throw_as_system_error_with_payload(HttpError e);

using HttpResult = boost::outcome_v2::result<nlohmann::json, HttpError>;

class HttpClient
{
public:
  HttpClient(std::string baseUrl, std::string instanceId, Backend* backend);
  HttpClient(HttpClient const&) = delete;
  HttpClient(HttpClient&&) = delete;
  HttpClient& operator=(HttpClient const&) = delete;
  HttpClient& operator=(HttpClient&&) = delete;

  ~HttpClient();

  tc::cotask<HttpResult> asyncGet(std::string_view target);
  tc::cotask<HttpResult> asyncPost(std::string_view target,
                                   nlohmann::json data);
  tc::cotask<HttpResult> asyncPost(std::string_view target);
  tc::cotask<HttpResult> asyncPatch(std::string_view target,
                                    nlohmann::json data);
  tc::cotask<HttpResult> asyncDelete(std::string_view target);

  std::string makeUrl(std::string_view target) const;
  std::string makeUrl(std::string_view target,
                      nlohmann::json const& query) const;
  std::string makeQueryString(nlohmann::json const& query) const;

  tc::cotask<void> deauthenticate();

  void setAccessToken(std::string_view accessToken);
  void setDeviceAuthData(
      Trustchain::DeviceId const& deviceId,
      Crypto::SignatureKeyPair const& deviceSignatureKeyPair);

private:
  std::string _baseUrl;
  std::string _instanceId;
  std::string _accessToken;
  Backend* _backend;

  Trustchain::DeviceId _deviceId;
  Crypto::SignatureKeyPair _deviceSignatureKeyPair;
  bool _isRevoked{};

  tc::shared_future<void> _authenticating = tc::make_ready_future().to_shared();

  tc::cotask<void> authenticate();
  HttpRequest makeRequest(HttpMethod method,
                          std::string_view url,
                          nlohmann::json const& data);
  HttpRequest makeRequest(HttpMethod method, std::string_view url);

  tc::cotask<HttpResult> authenticatedFetch(HttpRequest req);
  tc::cotask<HttpResult> fetch(HttpRequest req);
};
}
