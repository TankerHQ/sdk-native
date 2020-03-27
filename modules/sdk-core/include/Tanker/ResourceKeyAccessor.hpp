#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ResourceKeyStore.hpp>

#include <optional>

namespace Tanker::Users
{
class ILocalUserAccessor;
class IRequester;
}

namespace Tanker
{
class ResourceKeyAccessor
{
public:
  ResourceKeyAccessor(Users::IRequester* client,
                      Users::ILocalUserAccessor* localUserAccessor,
                      Groups::IAccessor* groupAccessor,
                      ProvisionalUsers::IAccessor* provisionalUsersAccessor,
                      ResourceKeyStore* resourceKeyStore);
  ResourceKeyAccessor() = delete;
  ResourceKeyAccessor(ResourceKeyAccessor const&) = delete;
  ResourceKeyAccessor(ResourceKeyAccessor&&) = delete;
  ResourceKeyAccessor& operator=(ResourceKeyAccessor const&) = delete;
  ResourceKeyAccessor& operator=(ResourceKeyAccessor&&) = delete;

  tc::cotask<std::optional<Crypto::SymmetricKey>> findKey(
      Trustchain::ResourceId const& resourceId);

private:
  Users::IRequester* _requester;
  Users::ILocalUserAccessor* _localUserAccessor;
  Groups::IAccessor* _groupAccessor;
  ProvisionalUsers::IAccessor* _provisionalUsersAccessor;
  ResourceKeyStore* _resourceKeyStore;
};
}
