#include <Tanker/Network/HttpClient.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Network/HttpHeaderMap.hpp>
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
    {"provisional_identity_already_attached", AppdErrc::ProvisionalIdentityAlreadyAttached},
    {"too_many_attempts", AppdErrc::TooManyAttempts},
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
    {"not_a_user_group_member", AppdErrc::NotAUserGroupMember},
    {"empty_user_group", AppdErrc::EmptyUserGroup},
    {"missing_user_group_members", AppdErrc::MissingUserGroupMembers},
    {"feature_not_enabled", AppdErrc::FeatureNotEnabled},
    {"conflict", AppdErrc::Conflict},
    {"invalid_authorization_code", AppdErrc::InvalidAuthorizationCode},
    {"oidc_provider_interaction_required", AppdErrc::OidcProviderInteractionRequired},
    {"oidc_provider_not_configured", AppdErrc::OidcProviderNotConfigured},
    {"oidc_provider_not_supported", AppdErrc::OidcProviderNotSupported},
};

AppdErrc getErrorFromCode(std::string_view code)
{
  if (auto it = appdErrorMap.find(code); it != appdErrorMap.end())
    return it->second;
  TERROR("Unknown server error: {}", code);
  return AppdErrc::UnknownError;
}

// We assume non-JSON responses come from a proxy or other middlebox
Exception newMiddleboxError(HttpResponse const& res, HttpRequest const& req)
{
  return Errors::formatEx(Errors::Errc::NetworkError,
                          "Request may have been intercepted by proxy, received non-JSON response for "
                          "{} {}, status: {}, body: {}",
                          httpMethodToString(req.method),
                          req.url,
                          res.statusCode,
                          res.body);
}

HttpError handleErrorResponse(HttpResponse const& res, HttpRequest const& req)
{
  auto contentType = res.headers.get(HttpHeader::CONTENT_TYPE);

  if (!(contentType && boost::algorithm::starts_with(*contentType, "application/json")))
    throw newMiddleboxError(res, req);

  try
  {
    auto const json = nlohmann::json::parse(res.body);
    auto error = json.at("error").get<HttpError>();
    error.method = req.method;
    error.href = req.url;
    return error;
  }
  catch (nlohmann::json::exception const& ex)
  {
    throw newMiddleboxError(res, req);
  }
}

HttpResult handleResponse(HttpResponse res, HttpRequest const& req)
{
  if (res.statusCode < 200 || res.statusCode >= 300)
  {
    return boost::outcome_v2::failure(handleErrorResponse(res, req));
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
    throw newMiddleboxError(res, req);
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
  throw Errors::formatEx(
      e.ec, "HTTP error occurred: {} {}: {} {}, traceID: {}", e.method, e.href, e.status, e.message, e.traceId);
}

HttpClient::HttpClient(std::string baseUrl, std::string instanceId, Backend* backend, SdkInfo const& info)
  : _baseUrl(std::move(baseUrl)), _instanceId(std::move(instanceId)), _backend(backend), _info(info)
{
  if (!_baseUrl.empty() && _baseUrl.back() != '/')
    _baseUrl += '/';
}

HttpClient::~HttpClient() = default;

void HttpClient::setAccessToken(std::string_view accessToken)
{
  _accessToken = fmt::format("Bearer {}", accessToken);
}

void HttpClient::setDeviceAuthData(Trustchain::DeviceId const& deviceId,
                                   Crypto::SignatureKeyPair const& deviceSignatureKeyPair)
{
  _deviceId = deviceId;
  _deviceSignatureKeyPair = deviceSignatureKeyPair;
}

// Do not call anything else than fetch here to avoid recursive calls
tc::cotask<void> HttpClient::authenticate()
{
  if (!_authenticating.is_ready())
  {
    TC_AWAIT(_authenticating);
    TC_RETURN();
  }

  _accessToken.clear();

  auto const doAuth = [&]() -> tc::cotask<void> {
    FUNC_TIMER(Net);

    auto const baseTarget = fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpMethod::Post, makeUrl(fmt::format("{}/challenges", baseTarget)));
    auto const challenge = TC_AWAIT(fetch(std::move(req))).value().at("challenge").get<std::string>();
    // NOTE: It is MANDATORY to check this prefix is valid, or the server
    // could get us to sign anything!
    // NOTE: Visual Studio cannot compile a u8 string correctly, so hardcode
    // U+1F512 in hex
    if (!boost::algorithm::starts_with(challenge, "\xF0\x9F\x94\x92 Auth Challenge. 1234567890."))
    {
      throw formatEx(Errors::Errc::InternalError,
                     "received auth challenge does not contain mandatory prefix, server "
                     "may not be up to date, or we may be under attack.");
    }
    auto const signature =
        Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(), _deviceSignatureKeyPair.privateKey);
    auto req2 = makeRequest(HttpMethod::Post,
                            makeUrl(fmt::format("{}/sessions", baseTarget)),
                            {{"signature", signature},
                             {"challenge", challenge},
                             {"signature_public_key", _deviceSignatureKeyPair.publicKey}});
    auto response = TC_AWAIT(fetch(std::move(req2))).value();
    auto accessToken = response.at("access_token").get<std::string>();

    setAccessToken(accessToken);
  };

  _authenticating = tc::async_resumable(doAuth).to_shared();

  TC_AWAIT(_authenticating);

  TC_RETURN();
}

tc::cotask<void> HttpClient::deauthenticate()
{
  if (_accessToken.empty())
    TC_RETURN();

  try
  {
    auto const baseTarget = fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", _deviceId));
    auto req = makeRequest(HttpMethod::Delete, makeUrl(fmt::format("{}/sessions", baseTarget)));
    auto res = TC_AWAIT(fetch(req));
    if (res.has_error())
    {
      auto const error = res.error();
      // HTTP status:
      //   204: session successfully deleted
      //   401: session already expired
      //   other: something unexpected happened -> ignore and continue closing
      //   ¯\_(ツ)_/¯
      if (error.status != 204 && error.status != 401)
        TERROR("Error while deauthenticating: {}: {}", error.ec, error.message);
    }
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Errors::Errc::NetworkError)
      TERROR("Error while deauthenticating: {}", e.what());
    else
      throw;
  }
}

std::string HttpClient::makeUrl(std::string_view target) const
{
  return fmt::format("{}{}", _baseUrl, target);
}

std::string HttpClient::makeUrl(std::string_view target, nlohmann::json const& query) const
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
      throw Errors::AssertionError("unknown type in HttpClient::makeQueryString");
    }
  }
  if (!out.empty())
    out.pop_back(); // remove the final '&'
  return out;
}

tc::cotask<HttpResult> HttpClient::asyncGet(std::string_view target)
{
  auto req = makeRequest(HttpMethod::Get, target);
  TC_RETURN(TC_AWAIT(authenticatedFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPost(std::string_view target, nlohmann::json data)
{
  auto req = makeRequest(HttpMethod::Post, target, std::move(data));
  TC_RETURN(TC_AWAIT(authenticatedFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncPatch(std::string_view target, nlohmann::json data)
{
  auto req = makeRequest(HttpMethod::Patch, target, std::move(data));
  TC_RETURN(TC_AWAIT(authenticatedFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncDelete(std::string_view target)
{
  auto req = makeRequest(HttpMethod::Delete, target);
  TC_RETURN(TC_AWAIT(authenticatedFetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncUnauthGet(std::string_view target)
{
  auto req = makeRequest(HttpMethod::Get, target);
  TC_RETURN(TC_AWAIT(fetch(std::move(req))));
}

tc::cotask<HttpResult> HttpClient::asyncUnauthPost(std::string_view target, nlohmann::json data)
{
  auto req = makeRequest(HttpMethod::Post, target, std::move(data));
  TC_RETURN(TC_AWAIT(fetch(std::move(req))));
}

HttpRequest HttpClient::makeRequest(HttpMethod method, std::string_view url, nlohmann::json const& data)
{
  auto req = makeRequest(method, url);
  req.headers.set({HttpHeader::CONTENT_TYPE, "application/json"});
  req.body = data.dump();
  return req;
}

HttpRequest HttpClient::makeRequest(HttpMethod method, std::string_view url)
{
  using namespace HttpHeader;

  HttpRequest req;
  req.method = method;
  req.url = url;

  req.headers = {{ACCEPT, "application/json"},
                 {TANKER_INSTANCE_ID, _instanceId},
                 {TANKER_SDK_TYPE, _info.sdkType},
                 {TANKER_SDK_VERSION, _info.version}};
  if (!_accessToken.empty())
    req.headers.set({AUTHORIZATION, _accessToken});

  return req;
}

tc::cotask<HttpResult> HttpClient::authenticatedFetch(HttpRequest req)
{
  using namespace HttpHeader;

  TC_AWAIT(_authenticating);
  if (!req.headers.get(AUTHORIZATION))
  {
    // No access token yet, authenticate before failing the first API call.
    //
    // Occurs in offline mode on the first authenticated call. This is also
    // the recovery process when this API call occurs after a previous
    // re-authentication failure (because authenticate() clears "_accessToken")
    TC_AWAIT(authenticate());
    req.headers.set(AUTHORIZATION, _accessToken);
  }

  auto response = TC_AWAIT(fetch(req));
  if (!response && response.error().ec == AppdErrc::InvalidToken)
  {
    // The access token we are using is invalid/expired.
    //
    // We could be in one of the following situations:
    //
    // 1. Another API call is already trying to re-authenticate
    if (!_authenticating.is_ready())
      TC_AWAIT(_authenticating);
    // 2. First re-authentication attempt after access token expiration
    else if (*req.headers.get(AUTHORIZATION) == _accessToken)
      TC_AWAIT(authenticate());
    // (else)
    // 3. Another API call already completed a re-authentication

    // We can safely retry now with _accessToken
    req.headers.set(AUTHORIZATION, _accessToken);
    TC_RETURN(TC_AWAIT(fetch(std::move(req))));
  }
  TC_RETURN(response);
}

tc::cotask<HttpResult> HttpClient::fetch(HttpRequest req)
{
  auto const lock = TC_AWAIT(_semaphore.get_scope_lock());

  FUNC_TIMER(Net);
  TDEBUG("{} {}", httpMethodToString(req.method), req.url);
  auto res = TC_AWAIT(_backend->fetch(req));
  TDEBUG("{} {}, {}", httpMethodToString(req.method), req.url, res.statusCode);
  TC_RETURN(handleResponse(std::move(res), req));
}

tc::cotask<std::string> HttpClient::asyncGetRedirectLocation(std::string_view target, std::optional<std::string> cookie)
{
  HttpRequest req;
  req.method = HttpMethod::Get;
  req.url = target;
  req.headers = {{HttpHeader::ACCEPT, "application/json"}};

  if (cookie)
    req.headers.set(HttpHeader::COOKIE, *cookie);

  auto const lock = TC_AWAIT(_semaphore.get_scope_lock());

  FUNC_TIMER(Net);
  TDEBUG("{} {}", httpMethodToString(req.method), req.url);
  auto res = TC_AWAIT(_backend->fetch(req));
  TDEBUG("{} {}, {}", httpMethodToString(req.method), req.url, res.statusCode);

  if (res.statusCode != 302)
  {
    outcome_throw_as_system_error_with_payload(handleErrorResponse(res, req));
  }

  auto const& location = res.headers.get(HttpHeader::LOCATION);
  if (!location)
  {
    throw Errors::formatEx(Errors::AppdErrc::InternalError,
                           "{} {}, status: 302; missing Location header in the response",
                           httpMethodToString(req.method),
                           req.url);
  }

  TC_RETURN(*location);
}
}
