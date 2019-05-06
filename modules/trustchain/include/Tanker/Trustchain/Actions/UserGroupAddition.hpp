#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition/v1.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <mpark/variant.hpp>
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
      (selfSignature, Crypto::Signature)

class UserGroupAddition
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(
      UserGroupAddition,
      (UserGroupAddition1),
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES)

public:
  using v1 = UserGroupAddition1;

  Nature nature() const;
  std::vector<std::uint8_t> signatureData() const;
  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);
};

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for UserGroupAddition.
std::uint8_t* to_serialized(std::uint8_t*, UserGroupAddition const&);
std::size_t serialized_size(UserGroupAddition const&);

void to_json(nlohmann::json&, UserGroupAddition const&);
}
}
}
