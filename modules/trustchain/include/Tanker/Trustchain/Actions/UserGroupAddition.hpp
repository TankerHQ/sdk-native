#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

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
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES \
  (groupId, GroupId), (previousGroupBlockHash, Crypto::Hash),    \
      (sealedPrivateEncryptionKeysForUsers,                      \
       SealedPrivateEncryptionKeysForUsers),                     \
      (selfSignature, Crypto::Signature)

class UserGroupAddition
{
public:
  using SealedPrivateEncryptionKeysForUsers =
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>>;

  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      UserGroupAddition,
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES)

public:
  UserGroupAddition(GroupId const&,
                    Crypto::Hash const&,
                    SealedPrivateEncryptionKeysForUsers const&);

  static constexpr Nature nature();

  std::vector<std::uint8_t> signatureData() const;

  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

  friend void from_serialized(Serialization::SerializedSource&,
                              UserGroupAddition&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(UserGroupAddition)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(UserGroupAddition)

constexpr Nature UserGroupAddition::nature()
{
  return Nature::UserGroupAddition;
}
}
}
}
