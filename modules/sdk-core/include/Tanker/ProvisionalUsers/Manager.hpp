#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Users
{
class ILocalUserAccessor;
}
namespace ProvisionalUsers
{
class Manager
{
public:
  Manager(Users::ILocalUserAccessor* localUserAccessor,
          Client* client,
          ProvisionalUsers::Accessor* provisionalUsersAccessor,
          ProvisionalUserKeysStore* provisionalUserKeysStore,
          Trustchain::TrustchainId const& trustchainId);

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);

  tc::cotask<void> verifyProvisionalIdentity(
      Unlock::Request const& unlockRequest);

  std::optional<Identity::SecretProvisionalIdentity> const&
  provisionalIdentity() const;

private:
  Users::ILocalUserAccessor* _localUserAccessor;
  Client* _client;
  ProvisionalUsers::Accessor* _provisionalUsersAccessor;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
  Trustchain::TrustchainId _trustchainId;

  std::optional<Identity::SecretProvisionalIdentity> _provisionalIdentity;
};
}
}
