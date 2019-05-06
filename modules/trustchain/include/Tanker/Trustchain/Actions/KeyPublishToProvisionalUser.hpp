#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class KeyPublishToProvisionalUser
{
public:
  KeyPublishToProvisionalUser() = default;
  KeyPublishToProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      ResourceId const& resourceId,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
      Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey);

  static constexpr Nature nature();

  Crypto::PublicSignatureKey const& appPublicSignatureKey() const;
  Crypto::PublicSignatureKey const& tankerPublicSignatureKey() const;
  ResourceId const& resourceId() const;
  Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey() const;

private:
  Crypto::PublicSignatureKey _appPublicSignatureKey;
  Crypto::PublicSignatureKey _tankerPublicSignatureKey;
  ResourceId _resourceId;
  Crypto::TwoTimesSealedSymmetricKey _twoTimesSealedSymmetricKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              KeyPublishToProvisionalUser&);
};

bool operator==(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);
bool operator!=(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);

constexpr Nature KeyPublishToProvisionalUser::nature()
{
  return Nature::KeyPublishToProvisionalUser;
}

void from_serialized(Serialization::SerializedSource&,
                     KeyPublishToProvisionalUser&);
std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToProvisionalUser const&);

constexpr std::size_t serialized_size(KeyPublishToProvisionalUser const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + ResourceId::arraySize +
         Crypto::TwoTimesSealedSymmetricKey::arraySize;
}

void to_json(nlohmann::json&, KeyPublishToProvisionalUser const&);
}
}
}
