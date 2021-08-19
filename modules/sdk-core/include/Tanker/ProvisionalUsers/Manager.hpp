#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Verification/Request.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Users
{
class ILocalUserAccessor;
}
namespace Verification
{
class Requester;
}
namespace ProvisionalUsers
{
class IRequester;

class Manager
{
public:
  Manager(Users::ILocalUserAccessor* localUserAccessor,
          IRequester* requester,
          Verification::Requester* unlockRequester,
          ProvisionalUsers::Accessor* provisionalUsersAccessor,
          ProvisionalUserKeysStore* provisionalUserKeysStore,
          Trustchain::TrustchainId const& trustchainId);

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity,
      Crypto::SymmetricKey const& userSecret);

  tc::cotask<void> verifyProvisionalIdentity(
      Verification::RequestWithVerif const& unlockRequest);

  std::optional<Identity::SecretProvisionalIdentity> const&
  provisionalIdentity() const;

private:
  tc::cotask<std::optional<ProvisionalUserKeys>> fetchProvisionalKeys(
      Identity::SecretProvisionalIdentity const& provisionalIdentity);
  tc::cotask<AttachResult> claimProvisionalIdentity(
      Identity::SecretProvisionalIdentity const& provisionalIdentity,
      Crypto::SymmetricKey const& userSecret);
  tc::cotask<AttachResult> claimProvisionalIdentityWithMethod(
      Identity::SecretProvisionalIdentity const& provisionalIdentity,
      Verification::VerificationMethod const& method,
      Crypto::SymmetricKey const& userSecret);

  Users::ILocalUserAccessor* _localUserAccessor;
  IRequester* _requester;
  Verification::Requester* _unlockRequester;
  ProvisionalUsers::Accessor* _provisionalUsersAccessor;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
  Trustchain::TrustchainId _trustchainId;

  std::optional<Identity::SecretProvisionalIdentity> _provisionalIdentity;
};
}
}
