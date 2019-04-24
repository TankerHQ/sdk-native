#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupAddition
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  constexpr Nature nature() const;

  UserGroupAddition() = default;
  UserGroupAddition(GroupId const&,
                    Crypto::Hash const&,
                    SealedPrivateEncryptionKeysForUsers const&,
                    Crypto::Signature const&);
  UserGroupAddition(GroupId const&,
                    Crypto::Hash const&,
                    SealedPrivateEncryptionKeysForUsers const&);

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

  GroupId const& groupId() const;
  Crypto::Hash const& previousGroupBlockHash() const;
  SealedPrivateEncryptionKeysForUsers const&
  sealedPrivateEncryptionKeysForUsers() const;
  Crypto::Signature const& selfSignature() const;

private:
  GroupId _groupId;
  Crypto::Hash _previousGroupBlockHash;
  SealedPrivateEncryptionKeysForUsers _sealedPrivateEncryptionKeysForUsers;
  Crypto::Signature _selfSignature;

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupAddition&);
};

bool operator==(UserGroupAddition const& lhs, UserGroupAddition const& rhs);
bool operator!=(UserGroupAddition const& lhs, UserGroupAddition const& rhs);

constexpr Nature UserGroupAddition::nature() const
{
  return Nature::UserGroupAddition;
}
}
}
}

#include <Tanker/Trustchain/Json/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Serialization/UserGroupAddition.hpp>
