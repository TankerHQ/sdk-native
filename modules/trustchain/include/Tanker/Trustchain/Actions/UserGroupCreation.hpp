#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupCreation
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  constexpr Nature nature() const;

  UserGroupCreation() = default;
  UserGroupCreation(Crypto::PublicSignatureKey const&,
                    Crypto::PublicEncryptionKey const&,
                    Crypto::SealedPrivateSignatureKey const&,
                    SealedPrivateEncryptionKeysForUsers const&,
                    Crypto::Signature const&);
  UserGroupCreation(Crypto::PublicSignatureKey const&,
                    Crypto::PublicEncryptionKey const&,
                    Crypto::SealedPrivateSignatureKey const&,
                    SealedPrivateEncryptionKeysForUsers const&);

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

  Crypto::PublicSignatureKey const& publicSignatureKey() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;
  Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey() const;
  SealedPrivateEncryptionKeysForUsers const&
  sealedPrivateEncryptionKeysForUsers() const;
  Crypto::Signature const& selfSignature() const;

private:
  Crypto::PublicSignatureKey _publicSignatureKey;
  Crypto::PublicEncryptionKey _publicEncryptionKey;
  Crypto::SealedPrivateSignatureKey _sealedPrivateSignatureKey;
  SealedPrivateEncryptionKeysForUsers _sealedPrivateEncryptionKeysForUsers;
  Crypto::Signature _selfSignature;

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupCreation&);
};

bool operator==(UserGroupCreation const& lhs, UserGroupCreation const& rhs);
bool operator!=(UserGroupCreation const& lhs, UserGroupCreation const& rhs);

constexpr Nature UserGroupCreation::nature() const
{
  return Nature::UserGroupCreation;
}
}
}
}

#include <Tanker/Trustchain/Json/UserGroupCreation.hpp>
#include <Tanker/Trustchain/Serialization/UserGroupCreation.hpp>
