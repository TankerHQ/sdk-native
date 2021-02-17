#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <fetchpp/client.hpp>
#include <fetchpp/http/url.hpp>

#include <boost/outcome/result.hpp>

#include <nlohmann/json_fwd.hpp>

#include <tconcurrent/coroutine.hpp>

#include <chrono>
#include <string_view>

namespace Tanker
{
struct HttpError
{
  fetchpp::http::verb method;
  std::string href;
  int status;
  Errors::AppdErrc ec;
  std::string message;
  std::string traceId;
};
}

// This is a hack needed to workaround a GCC 8 bug... remove it when we migrate
// to GCC 9
namespace boost::outcome_v2::trait
{
template <>
struct is_error_code_available<::Tanker::HttpError> : std::true_type
{
};
}

namespace Tanker
{
void from_json(nlohmann::json const& j, HttpError& e);

std::error_code make_error_code(HttpError const& e);
[[noreturn]] void outcome_throw_as_system_error_with_payload(HttpError e);

using HttpResult = boost::outcome_v2::result<nlohmann::json, HttpError>;

class HttpClient
{
public:
  enum class AuthResponse
  {
    Ok,
    Revoked,
  };

  HttpClient(fetchpp::http::url const& baseUrl,
             fetchpp::net::executor ex,
             std::chrono::nanoseconds timeout = std::chrono::seconds(30));
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

  [[nodiscard]] fetchpp::http::url makeUrl(std::string_view target) const;

  tc::cotask<AuthResponse> authenticate();
  tc::cotask<void> deauthenticate();

  void setHeader(std::string_view name, std::string_view value);
  void setAccessToken(std::string_view accessToken);
  void setDeviceAuthData(
      Trustchain::DeviceId const& deviceId,
      Crypto::SignatureKeyPair const& deviceSignatureKeyPair);

private:
  fetchpp::http::url _baseUrl;
  fetchpp::http::request_header<> _headers;
  fetchpp::client _cl;

  Trustchain::DeviceId _deviceId;
  Crypto::SignatureKeyPair _deviceSignatureKeyPair;
  bool _isRevoked{};

  tc::shared_future<void> _authenticating = tc::make_ready_future().to_shared();

  template <typename Request>
  tc::cotask<HttpResult> asyncFetch(fetchpp::client& cl, Request req);
};
}
