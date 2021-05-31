#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <tconcurrent/coroutine.hpp>

#include <boost/container/flat_map.hpp>

#include <optional>

namespace Tanker
{
namespace ProvisionalUsers
{
class IAccessor
{
public:
  using ProvisionalUserClaims =
      boost::container::flat_map<ProvisionalUserId, Trustchain::UserId>;

  virtual ~IAccessor() = default;

  virtual tc::cotask<std::optional<ProvisionalUserKeys>> pullEncryptionKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) = 0;
  virtual tc::cotask<std::optional<ProvisionalUserKeys>>
  findEncryptionKeysFromCache(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) = 0;

  virtual tc::cotask<
      boost::container::flat_map<ProvisionalUserId, Trustchain::UserId>>
  pullClaimingUserIds(std::vector<ProvisionalUserId> const& signatureKeys) = 0;

  virtual tc::cotask<void> refreshKeys() = 0;
};
}
}
