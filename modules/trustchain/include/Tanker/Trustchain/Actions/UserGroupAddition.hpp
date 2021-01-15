#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition/v1.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition/v2.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition/v3.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <boost/variant2/variant.hpp>
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
#define TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES  \
  (trustchainId, TrustchainId), (groupId, GroupId),               \
      (previousGroupBlockHash, Crypto::Hash),                     \
      (selfSignature, Crypto::Signature), (author, Crypto::Hash), \
      (signature, Crypto::Signature)

class UserGroupAddition
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(
      UserGroupAddition,
      (UserGroupAddition1, UserGroupAddition2, UserGroupAddition3),
      TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES)

public:
  using v1 = UserGroupAddition1;
  using v2 = UserGroupAddition2;
  using v3 = UserGroupAddition3;

  Nature nature() const;
  std::vector<std::uint8_t> signatureData() const;
};

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for UserGroupAddition.
std::uint8_t* to_serialized(std::uint8_t*, UserGroupAddition const&);
std::size_t serialized_size(UserGroupAddition const&);

void to_json(nlohmann::json&, UserGroupAddition const&);
}
}
}
