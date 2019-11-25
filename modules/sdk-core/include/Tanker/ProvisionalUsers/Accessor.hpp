#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/UserKeyStore.hpp>

namespace Tanker
{
namespace ProvisionalUsers
{
class Accessor : public IAccessor
{
public:
  Accessor(Client* client,
           ContactStore const* contactStore,
           UserKeyStore const* userKeyStore,
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
  ContactStore const* _contactStore;
  UserKeyStore const* _userKeyStore;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
};
}
}
