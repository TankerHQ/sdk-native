#include "HttpHelpers.hpp"

#include <Tanker/Crypto/Format/Format.hpp>

#include <nlohmann/json.hpp>

#include <tcurl.hpp>

namespace Tanker
{
tc::cotask<std::string> checkSessionToken(
    Trustchain::TrustchainId appId,
    std::string const& verificationApiToken,
    std::string const& publicIdentity,
    std::string const& sessionToken,
    nlohmann::json const& allowedMethods)
{
  auto const body = nlohmann::json({{"app_id", mgs::base64::encode(appId)},
                                    {"auth_token", verificationApiToken},
                                    {"public_identity", publicIdentity},
                                    {"session_token", sessionToken},
                                    {"allowed_methods", allowedMethods}});
  auto const message = body.dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url(fmt::format("{}/verification/session-token",
                               Tanker::TestConstants::trustchaindUrl()));
  request->add_header("Content-type: application/json");
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());

  tcurl::multi client;
  auto const response = TC_AWAIT(tcurl::read_all(client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode != 200)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "Failed to check session token");
  auto const jresponse =
      nlohmann::json::parse(response.data.begin(), response.data.end());
  TC_RETURN(jresponse.at("verification_method").get<std::string>());
}

tc::cotask<std::string> checkSessionToken(
    Trustchain::TrustchainId appId,
    std::string const& verificationApiToken,
    std::string const& publicIdentity,
    std::string const& sessionToken,
    std::string const& allowedMethod)
{
  TC_RETURN(TC_AWAIT(checkSessionToken(appId,
                                       verificationApiToken,
                                       publicIdentity,
                                       sessionToken,
                                       {{{"type", allowedMethod}}})));
}

tc::cotask<OidcIdToken> getOidcToken(TestConstants::OidcConfig& oidcConfig,
                                     std::string userName)
{
  auto const payload = nlohmann::json{
      {"client_id", oidcConfig.clientId},
      {"client_secret", oidcConfig.clientSecret},
      {"grant_type", "refresh_token"},
      {"refresh_token", oidcConfig.users.at(userName).refreshToken},
  };
  auto const message = payload.dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url("https://www.googleapis.com/oauth2/v4/token");
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());
  request->add_header("Content-type: application/json");

  tcurl::multi client;
  auto const response = TC_AWAIT(tcurl::read_all(client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode != 200)
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status google id token request: {}",
                           httpcode);
  auto const jresponse =
      nlohmann::json::parse(response.data.begin(), response.data.end());
  auto idToken = jresponse.at("id_token").get<std::string>();
  TC_RETURN((OidcIdToken{idToken, {}, {}}));
}
}
