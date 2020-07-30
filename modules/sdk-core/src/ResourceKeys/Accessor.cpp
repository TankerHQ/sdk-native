#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
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
tc::cotask<std::optional<Crypto::SymmetricKey>> Accessor::findKey(
    Trustchain::ResourceId const& resourceId)
{
  auto const result = TC_AWAIT(findKeys({resourceId}));
  if (result.empty())
    TC_RETURN(std::nullopt);
  TC_RETURN(std::get<Crypto::SymmetricKey>(result[0]));
}

// Try to get the key, in order:
// - from the resource key store
// - from the tanker server
// In all cases, we put the key in the resource key store
tc::cotask<ResourceKeys::KeysResult> Accessor::findKeys(
    std::vector<Trustchain::ResourceId> const& resourceIds)
{
  ResourceKeys::KeysResult out;
  std::vector<Trustchain::ResourceId> notFound;
  for (auto const& resourceId : resourceIds)
  {
    auto const key = (TC_AWAIT(_resourceKeyStore->findKey(resourceId)));
    if (key)
      out.push_back({*key, resourceId});
    else
      notFound.push_back(resourceId);
  }

  if (!notFound.empty())
  {
    auto const entries = TC_AWAIT(_requester->getKeyPublishes(notFound));
    for (auto const& action : entries)
    {
      auto const result =
          TC_AWAIT(ReceiveKey::decryptAndStoreKey(*_resourceKeyStore,
                                                  *_localUserAccessor,
                                                  *_groupAccessor,
                                                  *_provisionalUsersAccessor,
                                                  action));
      out.push_back(result);
    }
  }

  if (out.size() != resourceIds.size())
  {
    std::vector<Trustchain::ResourceId> requested = resourceIds;
    std::vector<Trustchain::ResourceId> got;
    std::vector<Trustchain::ResourceId> missing;

    std::transform(out.begin(),
                   out.end(),
                   std::back_inserter(got),
                   [](auto const& result) {
                     return std::get<Trustchain::ResourceId>(result);
                   });

    std::sort(requested.begin(), requested.end());
    std::sort(got.begin(), got.end());

    std::set_difference(requested.begin(),
                        requested.end(),
                        got.begin(),
                        got.end(),
                        std::back_inserter(missing));

    throw formatEx(Errors::Errc::InvalidArgument,
                   "can't find keys for resource IDs: {:s}",
                   fmt::join(missing, ", "));
  }

  TC_RETURN(out);
}
}
