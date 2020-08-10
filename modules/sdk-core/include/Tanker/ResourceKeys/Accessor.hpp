#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ResourceKeys/Store.hpp>

#include <optional>

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
      Trustchain::ResourceId const& resourceId);
  tc::cotask<ResourceKeys::KeysResult> findKeys(
      std::vector<Trustchain::ResourceId> const& resourceId);

private:
  Users::IRequester* _requester;
  Users::ILocalUserAccessor* _localUserAccessor;
  Groups::IAccessor* _groupAccessor;
  ProvisionalUsers::IAccessor* _provisionalUsersAccessor;
  Store* _resourceKeyStore;
};
}
