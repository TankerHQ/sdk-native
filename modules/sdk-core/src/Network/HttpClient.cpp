#include <Tanker/Network/HttpClient.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/algorithm/string.hpp>
#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/proxy.hpp>
#include <fetchpp/http/request.hpp>
#include <fetchpp/http/response.hpp>
#include <tconcurrent/asio_use_future.hpp>

#include <boost/container/flat_map.hpp>

#include <Tanker/Log/Log.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(HttpClient);

using namespace Tanker::Errors;
namespace http = fetchpp::http;

namespace Tanker::Network
{
namespace
{
boost::container::flat_map<std::string_view, AppdErrc> const appdErrorMap{
    {"internal_error", AppdErrc::InternalError},
    {"invalid_body", AppdErrc::InvalidBody},
    {"bad_request", AppdErrc::BadRequest},
    {"app_is_not_test", AppdErrc::TrustchainIsNotTest},
    {"app_not_found", AppdErrc::AppNotFound},
    {"device_not_found", AppdErrc::DeviceNotFound},
    {"provisional_identity_not_found", AppdErrc::ProvisionalIdentityNotFound},
    {"provisional_identity_already_attached",
     AppdErrc::ProvisionalIdentityAlreadyAttached},
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
    {"blocked", AppdErrc::Blocked},
    {"upgrade_required", AppdErrc::UpgradeRequired},
    {"invalid_challenge_signature", AppdErrc::InvalidChallengeSignature},
    {"invalid_challenge_public_key", AppdErrc::InvalidChallengePublicKey},
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
  TERROR("Unknown server error: {}", code);
  return AppdErrc::UnknownError;
}

HttpVerb fromFetchppVerb(fetchpp::http::verb verb)
{
  switch (verb)
  {
  case fetchpp::http::verb::get:
    return HttpVerb::get;
  case fetchpp::http::verb::post:
    return HttpVerb::post;
  case fetchpp::http::verb::put:
    return HttpVerb::put;
  case fetchpp::http::verb::patch:
    return HttpVerb::patch;
  case fetchpp::http::verb::delete_:
    return HttpVerb::delete_;
  default:
    throw Errors::AssertionError("unknown HTTP verb");
  }
}

fetchpp::http::verb toFetchppVerb(HttpVerb verb)
{
  switch (verb)
  {
  case HttpVerb::get:
    return fetchpp::http::verb::get;
  case HttpVerb::post:
    return fetchpp::http::verb::post;
  case HttpVerb::put:
    return fetchpp::http::verb::put;
  case HttpVerb::patch:
    return fetchpp::http::verb::patch;
  case HttpVerb::delete_:
    return fetchpp::http::verb::delete_;
  default:
    throw Errors::AssertionError("unknown HTTP verb");
  }
}

HttpResult handleResponse(http::response res, http::request const& req)
{
  TLOG_CATEGORY(HttpClient);

  if (http::to_status_class(res.result()) != http::status_class::successful)
  {
    auto const method = req.method();
    auto const href = req.uri().href();
    if (res.is_json())
    {
      auto const json = res.json();
      auto error = json.at("error").get<HttpError>();
      error.method = fromFetchppVerb(method);
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

HttpClient::HttpClient(std::string baseUrl, std::chrono::nanoseconds timeout)
  : _baseUrl(std::move(baseUrl)),
    _cl(tc::get_default_executor().get_io_service().get_executor(),
        timeout,
        Cacerts::create_ssl_context())
{
  auto proxies = fetchpp::http::proxy_from_environment();
  if (auto proxyIt = proxies.find(http::proxy_scheme::https);
      proxyIt != proxies.end())
    TINFO("HTTPS proxy detected: {}", proxyIt->second.url());
  _cl.set_proxies(std::move(proxies));
}

HttpClient::~HttpClient() = default;

void HttpClient::setAccessToken(std::string_view accessToken)
{
  _headers.set(fetchpp::http::field::authorization,
               fetchpp::http::authorization::bearer{accessToken});
}

void HttpClient::setHeader(std::string_view name, std::string_view value)
{
  _headers.set(name, value);
}

void HttpClient::setDeviceAuthData(
    Trustchain::DeviceId const& deviceId,
    Crypto::SignatureKeyPair const& deviceSignatureKeyPair)
{
  _deviceId = deviceId;
  _deviceSignatureKeyPair = deviceSignatureKeyPair;
}

// Do not call anything else than asyncFetchBase here to avoid recursive calls
tc::cotask<HttpClient::AuthResponse> HttpClient::authenticate()
{
  if (!_authenticating.is_ready())
  {
    TC_AWAIT(_authenticating);
    TC_RETURN(_isRevoked ? AuthResponse::Revoked : AuthResponse::Ok);
  }

  _headers.erase(fetchpp::http::field::authorization);

  auto const doAuth = [&]() -> tc::cotask<void> {
    FUNC_TIMER(Net);

    auto const baseTarget =
        fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpVerb::post,
                           makeUrl(fmt::format("{}/challenges", baseTarget)));
    assignHeader(req, _headers);
    auto const challenge = TC_AWAIT(asyncFetchBase(std::move(req)))
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
                     _deviceSignatureKeyPair.privateKey);
    auto req2 = makeRequest(
        HttpVerb::post,
        makeUrl(fmt::format("{}/sessions", baseTarget)),
        {{"signature", signature},
         {"challenge", challenge},
         {"signature_public_key", _deviceSignatureKeyPair.publicKey}});
    assignHeader(req2, _headers);
    auto response = TC_AWAIT(asyncFetchBase(std::move(req2))).value();
    auto accessToken = response.at("access_token").get<std::string>();
    _isRevoked = response.at("is_revoked").get<bool>();

    _headers.set(fetchpp::http::field::authorization,
                 fetchpp::http::authorization::bearer{std::move(accessToken)});
  };

  _authenticating = tc::async_resumable(doAuth).to_shared();

  TC_AWAIT(_authenticating);

  TC_RETURN(_isRevoked ? AuthResponse::Revoked : AuthResponse::Ok);
}

tc::cotask<void> HttpClient::deauthenticate()
{
  if (_headers.count(fetchpp::http::field::authorization) == 0)
    TC_RETURN();

  try
  {
    auto const baseTarget =
        fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpVerb::delete_,
                           makeUrl(fmt::format("{}/sessions", baseTarget)));
    assignHeader(req, _headers);
    TINFO("{} {}", req.method(), req.uri().href());
    auto res = TC_AWAIT(_cl.async_fetch(std::move(req), tc::asio::use_future));
    TINFO("{} {}, {} {}",
          req.method(),
          req.uri().href(),
          res.result_int(),
          http::obsolete_reason(res.result()));
    // HTTP status:
    //   204: session successfully deleted
    //   401: session already expired
    //   other: something unexpected happened -> ignore and continue closing
    //   ¯\_(ツ)_/¯
    if (res.result_int() != 204 && res.result_int() != 401)
      TERROR("Error while closing the network client: {}", res.text());
  }
  catch (boost::system::system_error const& e)
  {
    TERROR("Error while closing the network client: {}", e.what());
  }
}

std::string HttpClient::makeUrl(std::string_view target) const
{
  return fmt::format("{}{}", _baseUrl, target);
}

std::string HttpClient::makeQueryString(nlohmann::json const& query) const
{
  std::string out;
  for (auto const& elem : query.items())
  {
    if (elem.value().is_array())
    {
      for (auto const& item : elem.value())
      {
        out += fmt::format("{}={}&", elem.key(), item.get<std::string>());
      }
    }
    else if (elem.value().is_string())
    {
      out += fmt::format("{}={}&", elem.key(), elem.value().get<std::string>());
    }
    else
    {
      throw Errors::AssertionError(
          "unknown type in HttpClient::makeQueryString");
    }
  }
  if (!out.empty())
    out.pop_back(); // remove the final '&'
  return out;
}

tc::cotask<HttpResult> HttpClient::asyncGet(std::string_view target)
{
  auto req = makeRequest(HttpVerb::get, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target)
{
  auto req = makeRequest(HttpVerb::post, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target,
                                             nlohmann::json data)
{
  auto req = makeRequest(HttpVerb::post, makeUrl(target), std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPatch(std::string_view target,
                                              nlohmann::json data)
{
  auto req = makeRequest(HttpVerb::patch, makeUrl(target), std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncDelete(std::string_view target)
{
  auto req = makeRequest(HttpVerb::delete_, makeUrl(target));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

fetchpp::http::request HttpClient::makeRequest(HttpVerb verb,
                                               std::string_view url,
                                               nlohmann::json const& data)
{
  auto request = http::request(toFetchppVerb(verb), http::url(url));
  request.content(data.dump());
  return request;
}

fetchpp::http::request HttpClient::makeRequest(HttpVerb verb,
                                               std::string_view url)
{
  auto req = http::request(toFetchppVerb(verb), http::url(url));
  req.prepare_payload();
  return req;
}

template <typename Request>
tc::cotask<HttpResult> HttpClient::asyncFetch(Request req)
{
  TC_AWAIT(_authenticating);
  assignHeader(req, _headers);

  auto response = TC_AWAIT(asyncFetchBase(req));
  if (!response && response.error().ec == AppdErrc::InvalidToken)
  {
    TC_AWAIT(authenticate());
    assignHeader(req, _headers);
    TC_RETURN(TC_AWAIT(asyncFetchBase(std::move(req))));
  }
  TC_RETURN(response);
}

tc::cotask<HttpResult> HttpClient::asyncFetchBase(http::request req)
{
  try
  {
    TINFO("{} {}", req.method(), req.uri().href());
    auto res = TC_AWAIT(doAsyncFetch(req));
    TINFO("{} {}, {} {}",
          req.method(),
          req.uri().href(),
          res.result_int(),
          http::obsolete_reason(res.result()));
    TC_RETURN(handleResponse(std::move(res), req));
  }
  catch (boost::system::system_error const& e)
  {
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "{}: {}",
                           e.code().category().name(),
                           e.code().message());
  }
}

tc::cotask<fetchpp::http::response> HttpClient::doAsyncFetch(http::request req)
{
  TC_RETURN(TC_AWAIT(_cl.async_fetch(std::move(req), tc::asio::use_future)));
}
}
