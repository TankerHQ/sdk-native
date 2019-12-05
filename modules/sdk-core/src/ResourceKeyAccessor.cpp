#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeyAccessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
#include <Tanker/Trustchain/Block.hpp>

namespace Tanker
{
ResourceKeyAccessor::ResourceKeyAccessor(
    Client* client,
    TrustchainVerifier* verifier,
    Users::UserKeyStore* userKeyStore,
    Groups::IAccessor* groupAccessor,
    ProvisionalUsers::IAccessor* provisionalUsersAccessor,
    ResourceKeyStore* resourceKeyStore)
  : _client(client),
    _verifier(verifier),
    _userKeyStore(userKeyStore),
    _groupAccessor(groupAccessor),
    _provisionalUsersAccessor(provisionalUsersAccessor),
    _resourceKeyStore(resourceKeyStore)
{
}

// Try to get the key, in order:
// - from the resource key store
// - from the tanker server
// In all cases, we put the key in the resource key store
tc::cotask<std::optional<Crypto::SymmetricKey>> ResourceKeyAccessor::findKey(
    Trustchain::ResourceId const& resourceId)
{
  auto key = (TC_AWAIT(_resourceKeyStore->findKey(resourceId)));
  if (!key)
  {
    auto blocks =
        TC_AWAIT(_client->getKeyPublishes(gsl::make_span(&resourceId, 1)));
    for (auto const& block : blocks)
    {
      auto const keyPublish =
          blockToServerEntry(Serialization::deserialize<Trustchain::Block>(
              cppcodec::base64_rfc4648::decode(block)));
      auto keyEntry = TC_AWAIT(_verifier->verify(keyPublish));
      TC_AWAIT(ReceiveKey::decryptAndStoreKey(
          *_resourceKeyStore,
          *_userKeyStore,
          *_groupAccessor,
          *_provisionalUsersAccessor,
          keyEntry.action.get<Trustchain::Actions::KeyPublish>()));
    }
    key = TC_AWAIT(_resourceKeyStore->findKey(resourceId));
  }
  TC_RETURN(key);
}
}
