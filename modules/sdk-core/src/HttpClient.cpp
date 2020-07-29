#include <Tanker/HttpClient.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Network/SdkInfo.hpp>

#include <tconcurrent/asio_use_future.hpp>

#include <Tanker/Log/Log.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(HttpClient);

namespace Tanker
{
using namespace Tanker::Errors;
namespace http = fetchpp::http;
using JsonRequest = http::request<http::json_body>;

namespace
{
std::map<std::string_view, AppdErrc> const appdErrorMap{
    {"internal_error", AppdErrc::InternalError},
    {"invalid_body", AppdErrc::InvalidBody},
    {"invalid_origin", AppdErrc::InvalidOrigin},
    {"trustchain_is_not_test", AppdErrc::TrustchainIsNotTest},
    {"trustchain_not_found", AppdErrc::AppNotFound},
    {"device_not_found", AppdErrc::DeviceNotFound},
    {"device_revoked", AppdErrc::DeviceRevoked},
    {"too_many_attempts", AppdErrc::TooManyAttempts},
    {"verification_needed", AppdErrc::VerificationNeeded},
    {"invalid_passphrase", AppdErrc::InvalidPassphrase},
    {"invalid_verification_code", AppdErrc::InvalidVerificationCode},
    {"verification_code_expired", AppdErrc::VerificationCodeExpired},
    {"verification_code_not_found", AppdErrc::VerificationCodeNotFound},
    {"verification_method_not_set", AppdErrc::VerificationMethodNotSet},
    {"verification_key_not_found", AppdErrc::VerificationKeyNotFound},
    {"group_too_big", AppdErrc::GroupTooBig},
    {"invalid_delegation_signature", AppdErrc::InvalidDelegationSignature},
    {"invalid_oidc_id_token", AppdErrc::InvalidVerificationCode},
    {"user_not_found", AppdErrc::UserNotFound},
};

AppdErrc getErrorFromCode(std::string_view code)
{
  if (auto it = appdErrorMap.find(code); it != appdErrorMap.end())
    return it->second;
  return AppdErrc::UnknownError;
}

nlohmann::json handleResponse(http::response res)
{
  if (http::to_status_class(res.result()) != http::status_class::successful)
  {
    if (!(res.result() == http::status::not_found && res.is_json()))
    {
      assert(res.is_json());
      auto const& json = res.json();
      auto const code =
          getErrorFromCode(json.at("error").at("code").get<std::string>());
      throw Errors::formatEx(code,
                             "status: {}, message: {}",
                             res.result_int(),
                             json.at("error").at("message").get<std::string>());
    }
  }

  try
  {
    if (res.result() != http::status::no_content)
      return res.json();
    else
      return {};
  }
  catch (nlohmann::json::exception const& ex)
  {
    throw Errors::formatEx(Tanker::AppdErrc::InvalidBody,
                           "invalid http response format");
  }
}

template <typename Request>
tc::cotask<nlohmann::json> asyncFetch(fetchpp::client& cl, Request req)
{
  TINFO("{} {}", req.method_string(), req.uri().href());
  // TDEBUG("\n{}", req);
  auto res = TC_AWAIT(cl.async_fetch(std::move(req), tc::asio::use_future));
  TINFO("{} {}", res.result_int(), http::obsolete_reason(res.result()));
  // TDEBUG("\n{}\n", res);
  TC_RETURN(handleResponse(res));
}

template <typename Request, typename Header>
Request&& assignHeader(Request&& request, Header const& header)
{
  for (auto const& field : header)
    request.set(field.name_string(), field.value());
  request.set("Accept", "application/json");
  return std::forward<Request>(request);
}

template <http::verb Verb>
JsonRequest makeRequest(http::url url,
                        http::request_header<> const& header,
                        nlohmann::json data)
{
  return assignHeader(http::make_request<JsonRequest>(
                          Verb, std::move(url), {}, std::move(data)),
                      header);
}

template <http::verb Verb>
auto makeRequest(http::url url, http::request_header<> const& header)
{
  auto req = http::make_request(Verb, std::move(url));
  req.prepare_payload();
  return assignHeader(req, header);
}
}

HttpClient::HttpClient(http::url const& baseUrl,
                       Network::SdkInfo const& info,
                       fetchpp::net::executor ex,
                       std::chrono::nanoseconds timeout)
  : _baseUrl(
        fmt::format("/apps/{appId:#S}/", fmt::arg("appId", info.trustchainId)),
        baseUrl),
    _cl(ex, timeout)
{
  _headers.set("X-Tanker-SdkType", info.sdkType);
  _headers.set("X-Tanker-SdkVersion", info.version);
}

void HttpClient::setAccessToken(http::authorization::methods const& m)
{
  _headers.set(fetchpp::http::field::authorization, m);
}

http::url HttpClient::makeUrl(std::string_view target) const
{
  return http::url(target, _baseUrl);
}

tc::cotask<nlohmann::json> HttpClient::asyncGet(std::string_view target)
{
  auto req = makeRequest<http::verb::get>(makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<nlohmann::json> HttpClient::asyncPost(std::string_view target,
                                                 nlohmann::json data)
{
  auto req =
      makeRequest<http::verb::post>(makeUrl(target), _headers, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<nlohmann::json> HttpClient::asyncPost(std::string_view target)
{
  auto req = makeRequest<http::verb::post>(makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<nlohmann::json> HttpClient::asyncDelete(std::string_view target)
{
  auto req = makeRequest<http::verb::delete_>(makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

HttpClient::~HttpClient() = default;
}