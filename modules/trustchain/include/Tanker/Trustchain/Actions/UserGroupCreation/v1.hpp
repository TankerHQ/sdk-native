#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class UserGroupCreation1
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      UserGroupCreation1,
      (publicSignatureKey, Crypto::PublicSignatureKey),
      (publicEncryptionKey, Crypto::PublicEncryptionKey),
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey),
      (sealedPrivateEncryptionKeysForUsers,
       SealedPrivateEncryptionKeysForUsers),
      (selfSignature, Crypto::Signature))

public:
  constexpr Nature nature() const;

  UserGroupCreation1(Crypto::PublicSignatureKey const&,
                     Crypto::PublicEncryptionKey const&,
                     Crypto::SealedPrivateSignatureKey const&,
                     SealedPrivateEncryptionKeysForUsers const&);

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupCreation1&);
};

constexpr Nature UserGroupCreation1::nature() const
{
  return Nature::UserGroupCreation;
}
}
}
}

#include <Tanker/Trustchain/Json/UserGroupCreation/v1.hpp>
#include <Tanker/Trustchain/Serialization/UserGroupCreation/v1.hpp>
