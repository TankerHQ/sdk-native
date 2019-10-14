#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation/v2.hpp>
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
class UserGroupCreation
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(
      UserGroupCreation,
      (UserGroupCreation1, UserGroupCreation2),
      (publicSignatureKey, Crypto::PublicSignatureKey),
      (publicEncryptionKey, Crypto::PublicEncryptionKey),
      (sealedPrivateSignatureKey, Crypto::SealedPrivateSignatureKey),
      (selfSignature, Crypto::Signature))

public:
  using v1 = UserGroupCreation1;
  using v2 = UserGroupCreation2;

  Nature nature() const;
  std::vector<std::uint8_t> signatureData() const;
  Crypto::Signature const& selfSign(Crypto::PrivateSignatureKey const&);

private:
  friend std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation const&);
  friend std::size_t serialized_size(UserGroupCreation const&);
  friend void to_json(nlohmann::json&, UserGroupCreation const&);
};

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for UserGroupCreation.
std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation const&);
std::size_t serialized_size(UserGroupCreation const&);

void to_json(nlohmann::json&, UserGroupCreation const&);
}
}
}
