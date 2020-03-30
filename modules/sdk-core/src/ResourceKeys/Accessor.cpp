#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/IRequester.hpp>

TLOG_CATEGORY(ResourceKeys::Accessor);

namespace Tanker::ResourceKeys
{
Accessor::Accessor(Users::IRequester* requester,
                   Users::ILocalUserAccessor* localUserAccessor,
                   Groups::IAccessor* groupAccessor,
                   ProvisionalUsers::IAccessor* provisionalUsersAccessor,
                   Store* resourceKeyStore)
  : _requester(requester),
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
tc::cotask<std::optional<Crypto::SymmetricKey>> Accessor::findKey(
    Trustchain::ResourceId const& resourceId)
{
  auto key = (TC_AWAIT(_resourceKeyStore->findKey(resourceId)));
  if (!key)
  {
    auto const entries = Trustchain::fromBlocksToServerEntries(
        TC_AWAIT(_requester->getKeyPublishes(gsl::make_span(&resourceId, 1))));
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
