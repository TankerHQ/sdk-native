#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <range/v3/action/sort.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/set_algorithm.hpp>
#include <range/v3/view/transform.hpp>

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
    Crypto::SimpleResourceId const& resourceId)
{
  try
  {
    auto const result = TC_AWAIT(findKeys({resourceId}));
    TC_RETURN(result[0].key);
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Errors::Errc::InvalidArgument)
      TC_RETURN(std::nullopt);
    throw;
  }
}

tc::cotask<KeysResult> Accessor::findOrFetchKeys(
    gsl::span<Crypto::SimpleResourceId const> resourceIds)
{
  KeysResult out;
  std::vector<Crypto::SimpleResourceId> notFound;

  for (auto const& resourceId : resourceIds)
  {
    auto const key = TC_AWAIT(_resourceKeyStore->findKey(resourceId));
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
  TC_RETURN(std::move(out));
}

[[noreturn]] void Accessor::throwForMissingKeys(
    gsl::span<Crypto::SimpleResourceId const> resourceIds,
    KeysResult const& result)
{
  auto const requested =
      resourceIds | ranges::to<std::vector> | ranges::actions::sort;
  auto const got = result | ranges::views::transform(&KeyResult::id) |
                   ranges::to<std::vector> | ranges::actions::sort;
  auto const missing = ranges::views::set_difference(requested, got);

  throw formatEx(Errors::Errc::InvalidArgument,
                 "can't find keys for resource IDs: {:s}",
                 fmt::join(missing, ", "));
}

tc::cotask<KeysResult> Accessor::findKeys(
    std::vector<Crypto::SimpleResourceId> const& resourceIds)
{
  auto keys = TC_AWAIT(_cache.run(
      [&](std::vector<Crypto::SimpleResourceId> const& keys)
          -> tc::cotask<KeysResult> {
        TC_RETURN(TC_AWAIT(findOrFetchKeys(keys)));
      },
      resourceIds));

  if (keys.size() != resourceIds.size())
    throwForMissingKeys(resourceIds, keys);

  TC_RETURN(std::move(keys));
}
}
