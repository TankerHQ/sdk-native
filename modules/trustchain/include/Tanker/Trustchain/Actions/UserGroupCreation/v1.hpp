#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

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
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES   \
  (publicSignatureKey, Crypto::PublicSignatureKey),                   \
      (publicEncryptionKey, Crypto::PublicEncryptionKey),             \
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey), \
      (sealedPrivateEncryptionKeysForUsers,                           \
       SealedPrivateEncryptionKeysForUsers),                          \
      (selfSignature, Crypto::Signature)

class UserGroupCreation1
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION_2(
      UserGroupCreation1,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)

public:
  static constexpr Nature nature();

  UserGroupCreation1(
      TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& publicSignatureKey,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
      SealedPrivateEncryptionKeysForUsers const&
          sealedPrivateEncryptionKeysForUsers,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
      Crypto::PrivateSignatureKey const& devicePrivateSignatureKey);

  std::vector<std::uint8_t> signatureData() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupCreation1&);
};

constexpr Nature UserGroupCreation1::nature()
{
  return Nature::UserGroupCreation;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupCreation1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupCreation1)
}
}
}
