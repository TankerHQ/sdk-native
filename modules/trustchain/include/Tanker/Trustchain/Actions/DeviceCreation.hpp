#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
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
class DeviceCreation
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(
      DeviceCreation,
      (DeviceCreation1, DeviceCreation3),
      (trustchainId, TrustchainId),
      (ephemeralPublicSignatureKey, Crypto::PublicSignatureKey),
      (userId, UserId),
      (delegationSignature, Crypto::Signature),
      (publicSignatureKey, Crypto::PublicSignatureKey),
      (publicEncryptionKey, Crypto::PublicEncryptionKey),
      (author, Crypto::Hash),
      (hash, Crypto::Hash),
      (signature, Crypto::Signature))

public:
  // v2 is missing, it's on purpose. We removed the "reset" feature, and v2 can
  // be converted into a v1 if the lastReset field is zero-filled.
  using v1 = DeviceCreation1;
  using v3 = DeviceCreation3;

  using DeviceType = v3::DeviceType;

  Nature nature() const;
  bool isGhostDevice() const;

  std::vector<std::uint8_t> delegationSignatureData() const;

private:
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation const&);
  friend std::size_t serialized_size(DeviceCreation const&);
  friend void to_json(nlohmann::json&, DeviceCreation const&);
};

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation const& dc);
std::size_t serialized_size(DeviceCreation const& dc);

void to_json(nlohmann::json& j, DeviceCreation const& dc);
}
}
}
