#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeyAccessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>

TLOG_CATEGORY(ResourceKeyAccessor);

namespace Tanker
{
ResourceKeyAccessor::ResourceKeyAccessor(
    Client* client,
    Users::ILocalUserAccessor* localUserAccessor,
    Groups::IAccessor* groupAccessor,
    ProvisionalUsers::IAccessor* provisionalUsersAccessor,
    ResourceKeyStore* resourceKeyStore)
  : _client(client),
    _localUserAccessor(localUserAccessor),
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
    auto const entries = Trustchain::fromBlocksToServerEntries(
        TC_AWAIT(_client->getKeyPublishes(gsl::make_span(&resourceId, 1))));
    for (auto const& entry : entries)
    {
      if (auto const kp =
              entry.action().get_if<Trustchain::Actions::KeyPublish>())
      {
        TC_AWAIT(ReceiveKey::decryptAndStoreKey(*_resourceKeyStore,
                                                *_localUserAccessor,
                                                *_groupAccessor,
                                                *_provisionalUsersAccessor,
                                                *kp));
      }
      else
      {
        TERROR("Skipping non-keypublish block {} {}",
               entry.hash(),
               entry.action().nature());
      }
    }
    key = TC_AWAIT(_resourceKeyStore->findKey(resourceId));
  }
  TC_RETURN(key);
}
}
