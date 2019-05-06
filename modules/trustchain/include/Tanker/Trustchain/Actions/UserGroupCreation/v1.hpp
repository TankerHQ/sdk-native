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

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
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
  static constexpr Nature nature();

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

void from_serialized(Serialization::SerializedSource&, UserGroupCreation1&);
std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation1 const&);
std::size_t serialized_size(UserGroupCreation1 const&);

void to_json(nlohmann::json&, UserGroupCreation1 const&);

constexpr Nature UserGroupCreation1::nature()
{
  return Nature::UserGroupCreation;
}
}
}
}
