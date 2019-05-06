#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation3::DeviceCreation3(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::Signature const& delegationSignature,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
    Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& sealedPrivateUserEncryptionKey,
    DeviceType type)
  : DeviceCreation1(ephemeralPublicSignatureKey,
                    userId,
                    delegationSignature,
                    devicePublicSignatureKey,
                    devicePublicEncryptionKey),
    _publicUserEncryptionKey(publicUserEncryptionKey),
    _sealedPrivateUserEncryptionKey(sealedPrivateUserEncryptionKey),
    _isGhostDevice(type == DeviceType::GhostDevice)
{
}

DeviceCreation3::DeviceCreation3(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
    Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& sealedPrivateUserEncryptionKey,
    DeviceType type)
  : DeviceCreation1(ephemeralPublicSignatureKey,
                    userId,
                    devicePublicSignatureKey,
                    devicePublicEncryptionKey),
    _publicUserEncryptionKey(publicUserEncryptionKey),
    _sealedPrivateUserEncryptionKey(sealedPrivateUserEncryptionKey),
    _isGhostDevice(type == DeviceType::GhostDevice)
{
}

Crypto::PublicEncryptionKey const& DeviceCreation3::publicUserEncryptionKey()
    const
{
  return _publicUserEncryptionKey;
}

Crypto::SealedPrivateEncryptionKey const&
DeviceCreation3::sealedPrivateUserEncryptionKey() const
{
  return _sealedPrivateUserEncryptionKey;
}

bool DeviceCreation3::isGhostDevice() const
{
  return _isGhostDevice;
}

bool operator==(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs)
{
  return std::tie(static_cast<DeviceCreation1 const&>(lhs),
                  lhs.publicUserEncryptionKey(),
                  lhs.sealedPrivateUserEncryptionKey()) ==
             std::tie(static_cast<DeviceCreation1 const&>(rhs),
                      rhs.publicUserEncryptionKey(),
                      rhs.sealedPrivateUserEncryptionKey()) &&
         (lhs.isGhostDevice() == rhs.isGhostDevice());
}

bool operator!=(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceCreation3& dc)
{
  Serialization::deserialize_to(ss, static_cast<DeviceCreation1&>(dc));
  Serialization::deserialize_to(ss, dc._publicUserEncryptionKey);
  Serialization::deserialize_to(ss, dc._sealedPrivateUserEncryptionKey);
  dc._isGhostDevice = static_cast<bool>(ss.read(1)[0]);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation3 const& dc)
{
  it = Serialization::serialize(it, static_cast<DeviceCreation1 const&>(dc));
  it = Serialization::serialize(it, dc.publicUserEncryptionKey());
  it = Serialization::serialize(it, dc.sealedPrivateUserEncryptionKey());
  *it++ = static_cast<std::uint8_t>(dc.isGhostDevice());
  return it;
}

void to_json(nlohmann::json& j, DeviceCreation3 const& dc)
{
  j = static_cast<DeviceCreation1 const&>(dc);
  j["userKeyPair"]["publicEncryptionKey"] = dc.publicUserEncryptionKey();
  j["userKeyPair"]["encryptedPrivateEncryptionKey"] =
      dc.sealedPrivateUserEncryptionKey();
  j["is_ghost_device"] = dc.isGhostDevice();
}
}
}
}
