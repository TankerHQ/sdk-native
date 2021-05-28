#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupUpdate/v1.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <boost/variant2/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker::Trustchain::Actions
{
class UserGroupUpdate
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(
      UserGroupUpdate,
      (UserGroupUpdate1),
      (trustchainId, TrustchainId),
      (groupId, GroupId),
      (previousGroupBlockHash, Crypto::Hash),
      (previousKeyRotationBlockHash, Crypto::Hash),
      (publicSignatureKey, Crypto::PublicSignatureKey),
      (publicEncryptionKey, Crypto::PublicEncryptionKey),
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey),
      (sealedPreviousPrivateEncryptionKey, Crypto::SealedPrivateEncryptionKey),
      (selfSignatureWithCurrentKey, Crypto::Signature),
      (selfSignatureWithPreviousKey, Crypto::Signature),
      (author, Crypto::Hash),
      (signature, Crypto::Signature))

public:
  using v1 = UserGroupUpdate1;

  Nature nature() const;
  std::vector<std::uint8_t> signatureData() const;

private:
  friend std::uint8_t* to_serialized(std::uint8_t*, UserGroupUpdate const&);
  friend std::size_t serialized_size(UserGroupUpdate const&);
  friend void to_json(nlohmann::json&, UserGroupUpdate const&);
};

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for UserGroupUpdate.
std::uint8_t* to_serialized(std::uint8_t*, UserGroupUpdate const&);
std::size_t serialized_size(UserGroupUpdate const&);

void to_json(nlohmann::json&, UserGroupUpdate const&);
}
