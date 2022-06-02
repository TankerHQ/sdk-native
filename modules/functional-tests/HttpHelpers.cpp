#include "HttpHelpers.hpp"

#include <fetchpp/fetch.hpp>
#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/request.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Format/Format.hpp>

#include <tconcurrent/asio_use_future.hpp>
#include <tconcurrent/executor.hpp>

namespace Tanker
{
tc::cotask<std::string> checkSessionToken(
    Trustchain::TrustchainId appId,
    std::string const& verificationApiToken,
    std::string const& publicIdentity,
    std::string const& sessionToken,
    nlohmann::json const& allowedMethods)
{
  using namespace fetchpp::http;
  auto const body = nlohmann::json({{"app_id", mgs::base64::encode(appId)},
                                    {"auth_token", verificationApiToken},
                                    {"public_identity", publicIdentity},
                                    {"session_token", sessionToken},
                                    {"allowed_methods", allowedMethods}});
  auto req =
      fetchpp::http::request(verb::post,
                             url("/verification/session-token",
                                 url(Tanker::TestConstants::trustchaindUrl())));
  req.content(body.dump());
  req.set(field::accept, "application/json");
  auto const response = TC_AWAIT(fetchpp::async_fetch(
      tc::get_default_executor().get_io_service().get_executor(),
      std::move(req),
      tc::asio::use_future));
  if (response.result() != status::ok)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "Failed to check session token");
  TC_RETURN(response.json().at("verification_method").get<std::string>());
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

  using namespace fetchpp;

  auto const url = http::url("https://www.googleapis.com/oauth2/v4/token");
  auto req = http::request(http::verb::post, url);
  req.content(payload.dump());
  auto response = TC_AWAIT(fetchpp::async_fetch(
      tc::get_default_executor().get_io_service().get_executor(),
      Cacerts::get_ssl_context(),
      std::move(req),
      tc::asio::use_future));
  if (response.result() != http::status::ok)
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status google id token request: {}: {}",
                           response.result_int(),
                           http::obsolete_reason(response.result()));

  TC_RETURN(response.json().at("id_token").get<OidcIdToken>());
}
}
