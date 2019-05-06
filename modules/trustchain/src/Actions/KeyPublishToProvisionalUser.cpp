#include <Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToProvisionalUser::KeyPublishToProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey)
  : _appPublicSignatureKey(appPublicSignatureKey),
    _tankerPublicSignatureKey(tankerPublicSignatureKey),
    _resourceId(resourceId),
    _twoTimesSealedSymmetricKey(twoTimesSealedSymmetricKey)
{
}

Crypto::PublicSignatureKey const&
KeyPublishToProvisionalUser::appPublicSignatureKey() const
{
  return _appPublicSignatureKey;
}

Crypto::PublicSignatureKey const&
KeyPublishToProvisionalUser::tankerPublicSignatureKey() const
{
  return _tankerPublicSignatureKey;
}

ResourceId const& KeyPublishToProvisionalUser::resourceId() const
{
  return _resourceId;
}

Crypto::TwoTimesSealedSymmetricKey const&
KeyPublishToProvisionalUser::twoTimesSealedSymmetricKey() const
{
  return _twoTimesSealedSymmetricKey;
}

bool operator==(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return std::tie(lhs.appPublicSignatureKey(),
                  lhs.tankerPublicSignatureKey(),
                  lhs.resourceId(),
                  lhs.twoTimesSealedSymmetricKey()) ==
         std::tie(rhs.appPublicSignatureKey(),
                  rhs.tankerPublicSignatureKey(),
                  rhs.resourceId(),
                  rhs.twoTimesSealedSymmetricKey());
}

bool operator!=(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss,
                     KeyPublishToProvisionalUser& kp)
{
  Serialization::deserialize_to(ss, kp._appPublicSignatureKey);
  Serialization::deserialize_to(ss, kp._tankerPublicSignatureKey);
  Serialization::deserialize_to(ss, kp._resourceId);
  Serialization::deserialize_to(ss, kp._twoTimesSealedSymmetricKey);
}

std::uint8_t* to_serialized(std::uint8_t* it,
                            KeyPublishToProvisionalUser const& kp)
{
  it = Serialization::serialize(it, kp.appPublicSignatureKey());
  it = Serialization::serialize(it, kp.tankerPublicSignatureKey());
  it = Serialization::serialize(it, kp.resourceId());
  return Serialization::serialize(it, kp.twoTimesSealedSymmetricKey());
}

void to_json(nlohmann::json& j, KeyPublishToProvisionalUser const& kp)
{
  j["appPublicSignatureKey"] = kp.appPublicSignatureKey();
  j["tankerPublicSignatureKey"] = kp.tankerPublicSignatureKey();
  j["resourceId"] = kp.resourceId();
  j["twoTimesSealedSymmetricKey"] = kp.twoTimesSealedSymmetricKey();
}
}
}
}
