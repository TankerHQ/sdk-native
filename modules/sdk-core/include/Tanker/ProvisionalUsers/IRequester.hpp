#pragma once

#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>
#include <vector>

namespace Tanker::ProvisionalUsers
{

class IRequester
{
public:
  virtual tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
  getClaimBlocks() = 0;
  virtual tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail) = 0;
  virtual tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Unlock::Request const& request) = 0;
  virtual ~IRequester() = default;
};
}
