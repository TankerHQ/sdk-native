#include <Tanker/HttpClient.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/algorithm/string.hpp>
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
    {"invalid_token", AppdErrc::InvalidToken},
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
    nlohmann::json const& data)
{
  auto request = http::make_request<http::request<http::json_body>>(
      verb, std::move(url), {}, data);
  return request;
}

fetchpp::http::request<fetchpp::http::empty_body> makeRequest(
    fetchpp::http::verb verb, fetchpp::http::url url)
{
  auto req = http::make_request(verb, std::move(url));
  req.prepare_payload();
  return req;
}

template <typename Request>
tc::cotask<HttpResult> asyncFetchBase(fetchpp::client& cl, Request req)
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
  : _baseUrl(fmt::format("/v2/apps/{appId:#S}/",
                         fmt::arg("appId", info.trustchainId)),
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

void HttpClient::setDeviceAuthData(
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignaturePrivateKey)
{
  _deviceId = deviceId;
  _deviceSignaturePrivateKey = deviceSignaturePrivateKey;
}

// Do not call anything else than asyncFetchBase here to avoid recursive calls
tc::cotask<void> HttpClient::authenticate()
{
  if (!_authenticating.is_ready())
  {
    TC_AWAIT(_authenticating);
    TC_RETURN();
  }

  _headers.erase(fetchpp::http::field::authorization);

  auto const doAuth = [&]() -> tc::cotask<void> {
    FUNC_TIMER(Net);

    auto const baseTarget =
        fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(fetchpp::http::verb::post,
                           makeUrl(fmt::format("{}/challenges", baseTarget)));
    assignHeader(req, _headers);
    auto const challenge = TC_AWAIT(asyncFetchBase(_cl, std::move(req)))
                               .value()
                               .at("challenge")
                               .get<std::string>();
    // NOTE: It is MANDATORY to check this prefix is valid, or the server
    // could get us to sign anything!
    if (!boost::algorithm::starts_with(
            challenge, u8"\U0001F512 Auth Challenge. 1234567890."))
    {
      throw formatEx(
          Errors::Errc::InternalError,
          "received auth challenge does not contain mandatory prefix, server "
          "may not be up to date, or we may be under attack.");
    }
    auto const signature =
        Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                     _deviceSignaturePrivateKey);
    auto req2 =
        makeRequest(fetchpp::http::verb::post,
                    makeUrl(fmt::format("{}/sessions", baseTarget)),
                    {{"signature", signature}, {"challenge", challenge}});
    assignHeader(req2, _headers);
    auto accessToken = TC_AWAIT(asyncFetchBase(_cl, std::move(req2)))
                           .value()
                           .at("access_token")
                           .get<std::string>();

    _headers.set(fetchpp::http::field::authorization,
                 fetchpp::http::authorization::bearer{std::move(accessToken)});
  };

  _authenticating = tc::async_resumable(doAuth).to_shared();

  TC_AWAIT(_authenticating);
}

http::url HttpClient::makeUrl(std::string_view target) const
{
  return http::url(target, _baseUrl);
}

tc::cotask<HttpResult> HttpClient::asyncGet(std::string_view target)
{
  auto req = makeRequest(fetchpp::http::verb::get, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target)
{
  auto req = makeRequest(fetchpp::http::verb::post, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target,
                                             nlohmann::json data)
{
  auto req =
      makeRequest(fetchpp::http::verb::post, makeUrl(target), std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPatch(std::string_view target,
                                              nlohmann::json data)
{
  auto req =
      makeRequest(fetchpp::http::verb::patch, makeUrl(target), std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncDelete(std::string_view target)
{
  auto req = makeRequest(fetchpp::http::verb::delete_, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(_cl, std::move(req))));
}

template <typename Request>
tc::cotask<HttpResult> HttpClient::asyncFetch(fetchpp::client& cl, Request req)
{
  TC_AWAIT(_authenticating);
  assignHeader(req, _headers);

  auto response = TC_AWAIT(asyncFetchBase(cl, req));
  if (!response && response.error().ec == AppdErrc::InvalidToken)
  {
    TC_AWAIT(authenticate());
    assignHeader(req, _headers);
    TC_RETURN(TC_AWAIT(asyncFetchBase(cl, std::move(req))));
  }
  TC_RETURN(response);
}

HttpClient::~HttpClient() = default;
}
