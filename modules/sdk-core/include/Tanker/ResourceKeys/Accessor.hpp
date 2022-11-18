#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ResourceKeys/Store.hpp>
#include <Tanker/TaskCoalescer.hpp>

#include <gsl/gsl-lite.hpp>

namespace Tanker::Users
{
class ILocalUserAccessor;
class IRequester;
}

namespace Tanker::ResourceKeys
{
class Accessor
{
public:
  Accessor(Users::IRequester* client,
           Users::ILocalUserAccessor* localUserAccessor,
           Groups::IAccessor* groupAccessor,
           ProvisionalUsers::IAccessor* provisionalUsersAccessor,
           Store* resourceKeyStore);
  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(
      Crypto::SimpleResourceId const& resourceId);
  tc::cotask<KeysResult> findKeys(
      std::vector<Crypto::SimpleResourceId> const& resourceId);
  tc::cotask<boost::container::flat_map<Crypto::SimpleResourceId,
                                        Crypto::SymmetricKey>>
  tryFindKeys(std::vector<Crypto::SimpleResourceId> const& resourceId);

private:
  tc::cotask<KeysResult> findOrFetchKeys(
      gsl::span<Crypto::SimpleResourceId const> resourceIds);
  [[noreturn]] void throwForMissingKeys(
      gsl::span<Crypto::SimpleResourceId const> resourceIds,
      KeysResult const& result);

  Users::IRequester* _requester;
  Users::ILocalUserAccessor* _localUserAccessor;
  Groups::IAccessor* _groupAccessor;
  ProvisionalUsers::IAccessor* _provisionalUsersAccessor;
  Store* _resourceKeyStore;
  Tanker::TaskCoalescer<KeyResult> _cache;
};
}
