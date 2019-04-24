#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToUser
{
public:
  KeyPublishToUser() = default;
  KeyPublishToUser(Crypto::PublicEncryptionKey const&,
                   ResourceId const&,
                   Crypto::SealedSymmetricKey const&);

  constexpr Nature nature() const;

  Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey() const;
  ResourceId const& resourceId() const;
  Crypto::SealedSymmetricKey const& sealedSymmetricKey() const;

private:
  Crypto::PublicEncryptionKey _recipientPublicEncryptionKey;
  ResourceId _resourceId;
  Crypto::SealedSymmetricKey _sealedSymmetricKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToUser&);
};

bool operator==(KeyPublishToUser const&, KeyPublishToUser const&);
bool operator!=(KeyPublishToUser const&, KeyPublishToUser const&);

constexpr Nature KeyPublishToUser::nature() const
{
  return Nature::KeyPublishToUser;
}
}
}
}

#include <Tanker/Trustchain/Json/KeyPublishToUser.hpp>
#include <Tanker/Trustchain/Serialization/KeyPublishToUser.hpp>
