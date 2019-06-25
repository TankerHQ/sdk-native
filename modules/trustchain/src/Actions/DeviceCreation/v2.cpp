#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation2::DeviceCreation2(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::Signature const& delegationSignature,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
    Crypto::Hash const& lastReset)
  : DeviceCreation1(ephemeralPublicSignatureKey,
                    userId,
                    delegationSignature,
                    devicePublicSignatureKey,
                    devicePublicEncryptionKey),
    _lastReset(lastReset)
{
}

DeviceCreation2::DeviceCreation2(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
    Crypto::Hash const& lastReset)
  : DeviceCreation1(ephemeralPublicSignatureKey,
                    userId,
                    devicePublicSignatureKey,
                    devicePublicEncryptionKey),
    _lastReset(lastReset)
{
}

DeviceCreation1 const& DeviceCreation2::asDeviceCreation1() const
{
  if (!_lastReset.is_null())
  {
    throw Errors::Exception(
        Errc::InvalidLastResetField,
        "cannot convert DeviceCreation2 to DeviceCreation1: lastReset field is "
        "not zero-filled");
  }
  return static_cast<DeviceCreation1 const&>(*this);
}

Crypto::Hash const& DeviceCreation2::lastReset() const
{
  return _lastReset;
}

bool operator==(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs)
{
  return std::tie(static_cast<DeviceCreation1 const&>(lhs), lhs.lastReset()) ==
         std::tie(static_cast<DeviceCreation1 const&>(rhs), rhs.lastReset());
}

bool operator!=(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceCreation2& dc)
{
  Serialization::deserialize_to(ss, dc._lastReset);
  Serialization::deserialize_to(ss, static_cast<DeviceCreation1&>(dc));
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation2 const& dc)
{
  it = Serialization::serialize(it, dc.lastReset());
  return Serialization::serialize(it, static_cast<DeviceCreation1 const&>(dc));
}

void to_json(nlohmann::json& j, DeviceCreation2 const& dc)
{
  j = static_cast<DeviceCreation1 const&>(dc);
  j["lastReset"] = dc.lastReset();
}
}
}
}
