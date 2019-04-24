#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToProvisionalUser
{
public:
  KeyPublishToProvisionalUser() = default;
  KeyPublishToProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      ResourceId const& resourceId,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
      Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey);

  constexpr Nature nature() const;

  Crypto::PublicSignatureKey const& appPublicSignatureKey() const;
  Crypto::PublicSignatureKey const& tankerPublicSignatureKey() const;
  ResourceId const& resourceId() const;
  Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey() const;

private:
  Crypto::PublicSignatureKey _appPublicSignatureKey;
  Crypto::PublicSignatureKey _tankerPublicSignatureKey;
  ResourceId _resourceId;
  Crypto::TwoTimesSealedSymmetricKey _twoTimesSealedSymmetricKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToProvisionalUser&);
};

bool operator==(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);
bool operator!=(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);

constexpr Nature KeyPublishToProvisionalUser::nature() const
{
  return Nature::KeyPublishToProvisionalUser;
}
}
}
}

#include <Tanker/Trustchain/Json/KeyPublishToProvisionalUser.hpp>
#include <Tanker/Trustchain/Serialization/KeyPublishToProvisionalUser.hpp>
