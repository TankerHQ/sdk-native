#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceRevocation2::DeviceRevocation2(
    DeviceId const& deviceId,
    // avoid having both PublicEncryptionKey side by side
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& sealedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    SealedKeysForDevices const& sealedUserKeysForDevices)
  : _deviceId(deviceId),
    _publicEncryptionKey(publicEncryptionKey),
    _previousPublicEncryptionKey(previousPublicEncryptionKey),
    _sealedKeyForPreviousUserKey(sealedKeyForPreviousUserKey),
    _sealedUserKeysForDevices(sealedUserKeysForDevices)
{
}

DeviceId const& DeviceRevocation2::deviceId() const
{
  return _deviceId;
}

Crypto::PublicEncryptionKey const& DeviceRevocation2::publicEncryptionKey()
    const
{
  return _publicEncryptionKey;
}

Crypto::SealedPrivateEncryptionKey const&
DeviceRevocation2::sealedKeyForPreviousUserKey() const
{
  return _sealedKeyForPreviousUserKey;
}

Crypto::PublicEncryptionKey const&
DeviceRevocation2::previousPublicEncryptionKey() const
{
  return _previousPublicEncryptionKey;
}

auto DeviceRevocation2::sealedUserKeysForDevices() const
    -> SealedKeysForDevices const&
{
  return _sealedUserKeysForDevices;
}

bool operator==(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return std::tie(lhs.deviceId(),
                  lhs.publicEncryptionKey(),
                  lhs.sealedKeyForPreviousUserKey(),
                  lhs.previousPublicEncryptionKey(),
                  lhs.sealedUserKeysForDevices()) ==
         std::tie(rhs.deviceId(),
                  rhs.publicEncryptionKey(),
                  rhs.sealedKeyForPreviousUserKey(),
                  rhs.previousPublicEncryptionKey(),
                  rhs.sealedUserKeysForDevices());
}

bool operator!=(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
