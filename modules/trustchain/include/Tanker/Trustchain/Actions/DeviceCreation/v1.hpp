#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation1
{
public:
  DeviceCreation1() = default;
  DeviceCreation1(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::Signature const& delegationSignature,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey);
  DeviceCreation1(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey);

  static constexpr Nature nature();

  Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey() const;
  UserId const& userId() const;
  Crypto::Signature const& delegationSignature() const;
  Crypto::PublicSignatureKey const& publicSignatureKey() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;

  std::vector<std::uint8_t> signatureData() const;
  Crypto::Signature const& sign(Crypto::PrivateSignatureKey const&);

protected:
  Crypto::PublicSignatureKey _ephemeralPublicSignatureKey;
  UserId _userId;
  Crypto::Signature _delegationSignature;
  Crypto::PublicSignatureKey _publicSignatureKey;
  Crypto::PublicEncryptionKey _publicEncryptionKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation1&);
};

bool operator==(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs);
bool operator!=(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs);

void from_serialized(Serialization::SerializedSource&, DeviceCreation1&);
std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation1 const&);

constexpr std::size_t serialized_size(DeviceCreation1 const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + UserId::arraySize +
         Crypto::Signature::arraySize + Crypto::PublicEncryptionKey::arraySize;
}

void to_json(nlohmann::json&, DeviceCreation1 const&);

constexpr Nature DeviceCreation1::nature()
{
  return Nature::DeviceCreation;
}
}
}
}
