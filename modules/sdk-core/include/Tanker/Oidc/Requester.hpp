#pragma once

#include <Tanker/Oidc/IRequester.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/OidcAuthorizationCode.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Network
{
class HttpClient;
}

namespace Oidc
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Network::HttpClient* httpClient);

  tc::cotask<OidcAuthorizationCode>
  oidcSignIn(Trustchain::UserId const& userId, std::string const& providerId, std::string const& cookie) override;

private:
  Network::HttpClient* _httpClient;
};
}
}
