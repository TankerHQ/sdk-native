#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/OidcAuthorizationCode.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Oidc
{
class IRequester
{
public:
  virtual tc::cotask<OidcAuthorizationCode>
  oidcSignIn(Trustchain::UserId const& userId, std::string const& providerId, std::string const& cookie) = 0;

  virtual ~IRequester() = default;
};
}
