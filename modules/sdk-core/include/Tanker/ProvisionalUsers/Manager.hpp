#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Users
{
class LocalUser;
}
namespace ProvisionalUsers
{
class Manager
{
public:
  Manager(Users::LocalUser* localUser,
          Client* client,
          ProvisionalUsers::Accessor* provisionalUsersAccessor,
          ProvisionalUserKeysStore* provisionalUserKeysStore,
          Trustchain::TrustchainId const& trustchainId);

  tc::cotask<AttachResult> attachProvisionalIdentity(
      Crypto::EncryptionKeyPair const& lastUserKey,
      SSecretProvisionalIdentity const& sidentity);

  tc::cotask<void> verifyProvisionalIdentity(
      Crypto::EncryptionKeyPair const& lastUserKey,
      Unlock::Verification const& verification);

private:
  Users::LocalUser* _localUser;
  Client* _client;
  ProvisionalUsers::Accessor* _provisionalUsersAccessor;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
  Crypto::SymmetricKey _userSecret;
  Trustchain::TrustchainId _trustchainId;

  std::optional<Identity::SecretProvisionalIdentity> _provisionalIdentity;
};
}
}
