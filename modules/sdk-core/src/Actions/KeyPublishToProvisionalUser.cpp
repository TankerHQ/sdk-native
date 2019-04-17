#include <Tanker/Actions/KeyPublishToProvisionalUser.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
Trustchain::Actions::Nature KeyPublishToProvisionalUser::nature() const
{
  return Trustchain::Actions::Nature::KeyPublishToProvisionalUser;
}

std::vector<Index> KeyPublishToProvisionalUser::makeIndexes() const
{
  return {};
}

bool operator==(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return std::tie(lhs.appPublicSignatureKey,
                  lhs.tankerPublicSignatureKey,
                  lhs.resourceId,
                  lhs.key) == std::tie(rhs.appPublicSignatureKey,
                                       rhs.tankerPublicSignatureKey,
                                       rhs.resourceId,
                                       rhs.key);
}

bool operator!=(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return !(lhs == rhs);
}

KeyPublishToProvisionalUser deserializeKeyPublishToProvisionalUser(
    gsl::span<uint8_t const> data)
{
  KeyPublishToProvisionalUser kp;
  Serialization::SerializedSource ss(data);

  Serialization::deserialize_to(ss, kp.appPublicSignatureKey);
  Serialization::deserialize_to(ss, kp.tankerPublicSignatureKey);
  Serialization::deserialize_to(ss, kp.resourceId);
  Serialization::deserialize_to(ss, kp.key);
  return kp;
}

std::uint8_t* to_serialized(std::uint8_t* it,
                            KeyPublishToProvisionalUser const& kp)
{
  it = Serialization::serialize(it, kp.appPublicSignatureKey);
  it = Serialization::serialize(it, kp.tankerPublicSignatureKey);
  it = Serialization::serialize(it, kp.resourceId);
  return Serialization::serialize(it, kp.key);
}

void to_json(nlohmann::json& j, KeyPublishToProvisionalUser const& kp)
{
  j["appPublicSignatureKey"] = kp.appPublicSignatureKey;
  j["tankerPublicSignatureKey"] = kp.tankerPublicSignatureKey;
  j["resourceId"] = kp.resourceId;
  j["key"] = kp.key;
}
}
