#include <Tanker/HttpClient.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/SdkInfo.hpp>

#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/json_body.hpp>
#include <tconcurrent/asio_use_future.hpp>

#include <Tanker/Log/Log.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(HttpClient);

namespace Tanker
{
using namespace Tanker::Errors;
namespace http = fetchpp::http;

namespace
{
std::map<std::string_view, AppdErrc> const appdErrorMap{
    {"internal_error", AppdErrc::InternalError},
    {"invalid_body", AppdErrc::InvalidBody},
    {"invalid_origin", AppdErrc::InvalidOrigin},
    {"app_is_not_test", AppdErrc::TrustchainIsNotTest},
    {"app_not_found", AppdErrc::AppNotFound},
    {"device_not_found", AppdErrc::DeviceNotFound},
    {"provisional_identity_not_found", AppdErrc::ProvisionalIdentityNotFound},
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

template <typename Request, typename Header>
void assignHeader(Request& request, Header const& header)
{
  for (auto const& field : header)
    request.set(field.name_string(), field.value());
  request.set("Accept", "application/json");
}

AppdErrc getErrorFromCode(std::string_view code)
{
  if (auto it = appdErrorMap.find(code); it != appdErrorMap.end())
    return it->second;
  return AppdErrc::UnknownError;
}

template <typename Request>
HttpResult handleResponse(http::response res, Request const& req)
{
  TLOG_CATEGORY(HttpClient);

  if (http::to_status_class(res.result()) != http::status_class::successful)
  {
    auto const method = req.method();
    auto const href = req.uri().href();
    if (res.is_json())
    {
      auto const& json = res.json();
      auto error = json.at("error").get<HttpError>();
      error.method = method;
      error.href = href;
      return boost::outcome_v2::failure(std::move(error));
    }
    else
    {
      throw Errors::formatEx(Errors::AppdErrc::InternalError,
                             "{} {}, status: {}",
                             method,
                             href,
                             res.result_int());
    }
  }

  try
  {
    if (res.result() != http::status::no_content)
      return boost::outcome_v2::success(res.json());
    else
      return boost::outcome_v2::success(nlohmann::json(nullptr));
  }
  catch (nlohmann::json::exception const& ex)
  {
    throw Errors::formatEx(Errors::AppdErrc::InternalError,
                           "invalid http response format");
  }
}

fetchpp::http::request<fetchpp::http::json_body> makeRequest(
    fetchpp::http::verb verb,
    fetchpp::http::url url,
    fetchpp::http::request_header<> const& header,
    nlohmann::json const& data)
{
  auto request = http::make_request<http::request<http::json_body>>(
      verb, std::move(url), {}, data);
  assignHeader(request, header);
  return request;
}

fetchpp::http::request<fetchpp::http::empty_body> makeRequest(
    fetchpp::http::verb verb,
    fetchpp::http::url url,
    fetchpp::http::request_header<> const& header)
{
  auto req = http::make_request(verb, std::move(url));
  req.prepare_payload();
  assignHeader(req, header);
  return req;
}

template <typename Request>
tc::cotask<HttpResult> asyncFetch(fetchpp::client& cl, Request req)
{
  TLOG_CATEGORY(HttpClient);
  TINFO("{} {}", req.method(), req.uri().href());
  auto res = TC_AWAIT(cl.async_fetch(std::move(req), tc::asio::use_future));
  TINFO("{} {}, {} {}",
        req.method(),
        req.uri().href(),
        res.result_int(),
        http::obsolete_reason(res.result()));
  TC_RETURN(handleResponse(res, req));
}
}

void from_json(nlohmann::json const& j, HttpError& e)
{
  auto const strCode = j.at("code").get<std::string>();

  e.ec = getErrorFromCode(strCode);
  j.at("message").get_to(e.message);
  j.at("status").get_to(e.status);
  j.at("trace_id").get_to(e.traceId);
}

std::error_code make_error_code(HttpError const& e)
{
  return e.ec;
}

[[noreturn]] void outcome_throw_as_system_error_with_payload(HttpError e)
{
  throw Errors::formatEx(e.ec,
                         "HTTP error occurred: {} {}: {} {}, traceID: {}",
                         e.method,
                         e.href,
                         e.status,
                         e.message,
                         e.traceId);
}

HttpClient::HttpClient(http::url const& baseUrl,
                       SdkInfo const& info,
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

void HttpClient::setAccessToken(std::string accessToken)
{
  _headers.set(fetchpp::http::field::authorization,
               fetchpp::http::authorization::bearer{std::move(accessToken)});
}

http::url HttpClient::makeUrl(std::string_view target) const
{
  return http::url(target, _baseUrl);
}

tc::cotask<HttpResult> HttpClient::asyncGet(std::string_view target)
{
  auto req = makeRequest(fetchpp::http::verb::get, makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target)
{
  auto req = makeRequest(fetchpp::http::verb::post, makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target,
                                             nlohmann::json data)
{
  auto req = makeRequest(
      fetchpp::http::verb::post, makeUrl(target), _headers, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPatch(std::string_view target,
                                              nlohmann::json data)
{
  auto req = makeRequest(
      fetchpp::http::verb::patch, makeUrl(target), _headers, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncDelete(std::string_view target)
{
  auto req =
      makeRequest(fetchpp::http::verb::delete_, makeUrl(target), _headers);
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

HttpClient::~HttpClient() = default;
}