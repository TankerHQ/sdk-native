#pragma once

#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToUserGroup
{
public:
  KeyPublishToUserGroup() = default;
  KeyPublishToUserGroup(Crypto::PublicEncryptionKey const&,
                        Crypto::Mac const&,
                        Crypto::SealedSymmetricKey const&);

  constexpr Nature nature() const;

  Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey() const;
  Crypto::Mac const& mac() const;
  Crypto::SealedSymmetricKey const& sealedSymmetricKey() const;

private:
  Crypto::PublicEncryptionKey _recipientPublicEncryptionKey;
  Crypto::Mac _mac;
  Crypto::SealedSymmetricKey _sealedSymmetricKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUserGroup&);
};

bool operator==(KeyPublishToUserGroup const&, KeyPublishToUserGroup const&);
bool operator!=(KeyPublishToUserGroup const&, KeyPublishToUserGroup const&);

constexpr Nature KeyPublishToUserGroup::nature() const
{
  return Nature::KeyPublishToUserGroup;
}
}
}
}

#include <Tanker/Trustchain/Json/KeyPublishToUserGroup.hpp>
#include <Tanker/Trustchain/Serialization/KeyPublishToUserGroup.hpp>
