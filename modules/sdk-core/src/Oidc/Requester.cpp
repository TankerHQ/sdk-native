
#include <Tanker/Oidc/Requester.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Utils.hpp>

#include <fmt/format.h>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Oidc
{
Requester::Requester(Network::HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<OidcAuthorizationCode> Requester::oidcSignIn(Trustchain::UserId const& userId,
                                                        std::string const& providerId,
                                                        std::string const& cookie)
{
  auto const query = nlohmann::json{{"user_id", mgs::base64url_nopad::encode(userId)}};
  auto signinUrl =
      _httpClient->makeUrl(fmt::format("oidc/{providerId}/signin", fmt::arg("providerId", providerId)), query);
  auto const authorizationLocation = TC_AWAIT(_httpClient->asyncGetRedirectLocation(signinUrl));

  auto const callbackLocation =
      TC_AWAIT(_httpClient->asyncGetRedirectLocation(authorizationLocation, cookie));

  auto const resp = TC_AWAIT(_httpClient->asyncUnauthGet(callbackLocation)).value();

  auto const code = resp.at("code").get<std::string>();
  auto const state = resp.at("state").get<std::string>();

  TC_RETURN((OidcAuthorizationCode{providerId, code, state}));
}
}
