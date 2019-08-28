#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <optional.hpp>

namespace Tanker
{
class ResourceKeyAccessor
{
public:
  ResourceKeyAccessor(Client* client,
                      TrustchainVerifier* verifier,
                      UserKeyStore* userKeyStore,
                      GroupAccessor* groupAccessor,
                      ProvisionalUserKeysStore* provisionalKeyStore,
                      ResourceKeyStore* resourceKeyStore);
  ResourceKeyAccessor() = delete;
  ResourceKeyAccessor(ResourceKeyAccessor const&) = delete;
  ResourceKeyAccessor(ResourceKeyAccessor&&) = delete;
  ResourceKeyAccessor& operator=(ResourceKeyAccessor const&) = delete;
  ResourceKeyAccessor& operator=(ResourceKeyAccessor&&) = delete;

  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findKey(
      Trustchain::ResourceId const& resourceId);

private:
  Client* _client;
  TrustchainVerifier* _verifier;
  UserKeyStore* _userKeyStore;
  GroupAccessor* _groupAccessor;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
  ResourceKeyStore* _resourceKeyStore;
};
}
