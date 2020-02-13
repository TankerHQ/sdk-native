#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

namespace Tanker::Users
{
class ContactStore;
class LocalUser;
}

namespace Tanker
{
class ProvisionalUserKeysStore;
}

namespace Tanker::ProvisionalUsers
{

class Accessor : public IAccessor
{
public:
  Accessor(Client* client,
           Users::ContactStore const* contactStore,
           Users::LocalUser const* localUser,
           ProvisionalUserKeysStore* provisionalUserKeysStore);

  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  tc::cotask<std::optional<ProvisionalUserKeys>> pullEncryptionKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;
  tc::cotask<std::optional<ProvisionalUserKeys>> findEncryptionKeysFromCache(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;

  tc::cotask<void> refreshKeys() override;

private:
  Client* _client;
  Users::ContactStore const* _contactStore;
  Users::LocalUser const* _localUser;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
};
}
