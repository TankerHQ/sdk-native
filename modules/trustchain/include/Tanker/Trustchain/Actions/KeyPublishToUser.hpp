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
class KeyPublishToUser
{
public:
  KeyPublishToUser() = default;
  KeyPublishToUser(Crypto::PublicEncryptionKey const&,
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
