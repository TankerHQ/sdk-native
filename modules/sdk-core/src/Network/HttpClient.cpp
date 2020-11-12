#include <Tanker/Network/HttpClient.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>

#include <Tanker/Log/Log.hpp>

#include <nlohmann/json.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(HttpClient);

using namespace Tanker::Errors;

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

AppdErrc getErrorFromCode(std::string_view code)
{
  if (auto it = appdErrorMap.find(code); it != appdErrorMap.end())
    return it->second;
  TERROR("Unknown server error: {}", code);
  return AppdErrc::UnknownError;
}

HttpResult handleResponse(HttpResponse res, HttpRequest const& req)
{
  if (res.statusCode / 100 != 2)
  {
    if (boost::algorithm::starts_with(res.contentType, "application/json"))
    {
      auto const json = nlohmann::json::parse(res.body);
      auto error = json.at("error").get<HttpError>();
      error.method = req.method;
      error.href = req.url;
      return boost::outcome_v2::failure(std::move(error));
    }
    else
    {
      throw Errors::formatEx(Errors::AppdErrc::InternalError,
                             "{} {}, status: {}",
                             httpMethodToString(req.method),
                             req.url,
                             res.statusCode);
    }
  }

  try
  {
    if (res.statusCode != 204)
      return boost::outcome_v2::success(nlohmann::json::parse(res.body));
    else
      return boost::outcome_v2::success(nlohmann::json(nullptr));
  }
  catch (nlohmann::json::exception const& ex)
  {
    throw Errors::formatEx(Errors::AppdErrc::InternalError,
                           "invalid http response format: {}",
                           res.body);
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

HttpClient::HttpClient(std::string baseUrl,
                       std::string instanceId,
                       Backend* backend)
  : _baseUrl(std::move(baseUrl)),
    _instanceId(std::move(instanceId)),
    _backend(backend)
{
}

HttpClient::~HttpClient() = default;

void HttpClient::setAccessToken(std::string_view accessToken)
{
  _accessToken = fmt::format("Bearer {}", accessToken);
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

  _accessToken.clear();

  auto const doAuth = [&]() -> tc::cotask<void> {
    FUNC_TIMER(Net);

    auto const baseTarget =
        fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpMethod::Post,
                           makeUrl(fmt::format("{}/challenges", baseTarget)));
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
        HttpMethod::Post,
        makeUrl(fmt::format("{}/sessions", baseTarget)),
        {{"signature", signature},
         {"challenge", challenge},
         {"signature_public_key", _deviceSignatureKeyPair.publicKey}});
    auto response = TC_AWAIT(asyncFetchBase(std::move(req2))).value();
    auto accessToken = response.at("access_token").get<std::string>();
    _isRevoked = response.at("is_revoked").get<bool>();

    setAccessToken(accessToken);
  };

  _authenticating = tc::async_resumable(doAuth).to_shared();

  TC_AWAIT(_authenticating);

  TC_RETURN(_isRevoked ? AuthResponse::Revoked : AuthResponse::Ok);
}

tc::cotask<void> HttpClient::deauthenticate()
{
  if (_accessToken.empty())
    TC_RETURN();

  try
  {
    auto const baseTarget =
        fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpMethod::Delete,
                           makeUrl(fmt::format("{}/sessions", baseTarget)));
    TINFO("{} {}", httpMethodToString(req.method), req.url);
    auto res = TC_AWAIT(_backend->fetch(req));
    TINFO("{} {}, {}", httpMethodToString(req.method), req.url, res.statusCode);
    // HTTP status:
    //   204: session successfully deleted
    //   401: session already expired
    //   other: something unexpected happened -> ignore and continue closing
    //   ¯\_(ツ)_/¯
    if (res.statusCode != 204 && res.statusCode != 401)
      TERROR("Error while deauthenticating: {}", res.body);
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Errors::Errc::NetworkError)
      TERROR("Error while deauthenticating: {}", e.what());
    else
      throw;
  }
}

tc::cotask<void> HttpClient::stop()
{
  TC_AWAIT(_backend->stop());
}

std::string HttpClient::makeUrl(std::string_view target) const
{
  return fmt::format("{}{}", _baseUrl, target);
}

std::string HttpClient::makeUrl(std::string_view target,
                                nlohmann::json const& query) const
{
  return fmt::format("{}{}?{}", _baseUrl, target, makeQueryString(query));
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
  auto req = makeRequest(HttpMethod::Get, target);
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target)
{
  auto req = makeRequest(HttpMethod::Post, target);
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target,
                                             nlohmann::json data)
{
  auto req = makeRequest(HttpMethod::Post, target, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPatch(std::string_view target,
                                              nlohmann::json data)
{
  auto req = makeRequest(HttpMethod::Patch, target, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPut(std::string_view target,
                                            nlohmann::json data)
{
  auto req =
      makeRequest(HttpMethod::Put, target, std::move(data));
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncDelete(std::string_view target)
{
  auto req = makeRequest(HttpMethod::Delete, target);
  TC_RETURN(TC_AWAIT(asyncFetch(std::move(req))));
}

HttpRequest HttpClient::makeRequest(HttpMethod method,
                                    std::string_view url,
                                    nlohmann::json const& data)
{
  HttpRequest req;
  req.method = method;
  req.url = url;
  req.body = data.dump();
  req.instanceId = _instanceId;
  req.authorization = _accessToken;
  return req;
}

HttpRequest HttpClient::makeRequest(HttpMethod method, std::string_view url)
{
  HttpRequest req;
  req.method = method;
  req.url = url;
  req.instanceId = _instanceId;
  req.authorization = _accessToken;
  return req;
}

tc::cotask<HttpResult> HttpClient::asyncFetch(HttpRequest req)
{
  TC_AWAIT(_authenticating);

  auto response = TC_AWAIT(asyncFetchBase(req));
  if (!response && response.error().ec == AppdErrc::InvalidToken)
  {
    TC_AWAIT(authenticate());
    req.authorization = _accessToken;
    TC_RETURN(TC_AWAIT(asyncFetchBase(std::move(req))));
  }
  TC_RETURN(response);
}

tc::cotask<HttpResult> HttpClient::asyncFetchBase(HttpRequest req)
{
  TINFO("{} {}", httpMethodToString(req.method), req.url);
  auto res = TC_AWAIT(_backend->fetch(req));
  TINFO("{} {}, {}", httpMethodToString(req.method), req.url, res.statusCode);
  TC_RETURN(handleResponse(std::move(res), req));
}
}
