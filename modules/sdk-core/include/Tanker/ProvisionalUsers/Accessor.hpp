#pragma once

#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>
#include <Tanker/Users/IUserAccessor.hpp>

namespace Tanker::Users
{
class ILocalUserAccessor;
}

namespace Tanker
{
class ProvisionalUserKeysStore;
}

namespace Tanker::ProvisionalUsers
{
class IRequester;

class Accessor : public IAccessor
{
public:
  Accessor(IRequester* request,
           Users::IUserAccessor* userAccessor,
           Users::ILocalUserAccessor* localUser,
           ProvisionalUserKeysStore* provisionalUserKeysStore);

  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  tc::cotask<std::optional<ProvisionalUserKeys>> pullEncryptionKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey, Crypto::PublicSignatureKey const& tankerPublicSigKey) override;
  tc::cotask<std::optional<ProvisionalUserKeys>> findEncryptionKeysFromCache(
      Crypto::PublicSignatureKey const& appPublicSigKey, Crypto::PublicSignatureKey const& tankerPublicSigKey) override;

  tc::cotask<void> refreshKeys() override;

private:
  IRequester* _requester;
  Users::IUserAccessor* _userAccessor;
  Users::ILocalUserAccessor* _localUserAccessor;
  ProvisionalUserKeysStore* _provisionalUserKeysStore;
};
}
