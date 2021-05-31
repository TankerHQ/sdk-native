#pragma once

#include <Tanker/ProvisionalUsers/ProvisionalUserId.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/UserId.hpp>
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
  getClaimBlocks(Trustchain::UserId const& userId) = 0;
  virtual tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
  getClaimBlocks(std::vector<ProvisionalUserId> const& provisionalUserIds) = 0;
  virtual tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys() = 0;
  virtual tc::cotask<TankerSecretProvisionalIdentity>
  getProvisionalIdentityKeys(Unlock::Request const& request) = 0;
  virtual tc::cotask<void> claimProvisionalIdentity(
      Trustchain::Actions::ProvisionalIdentityClaim const& claimAction) = 0;
  virtual ~IRequester() = default;
};
}
