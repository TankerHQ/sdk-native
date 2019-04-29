#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
constexpr Nature DeviceCreation3::nature;

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
}
}
}
