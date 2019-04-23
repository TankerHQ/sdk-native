#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToDevice::KeyPublishToDevice(DeviceId const& recipient,
                                       Crypto::Mac const& mac,
                                       Crypto::EncryptedSymmetricKey const& key)
  : _recipient(recipient), _mac(mac), _key(key)
{
}

DeviceId const& KeyPublishToDevice::recipient() const
{
  return _recipient;
}

Crypto::Mac const& KeyPublishToDevice::mac() const
{
  return _mac;
}

Crypto::EncryptedSymmetricKey const& KeyPublishToDevice::encryptedSymmetricKey()
    const
{
  return _key;
}

bool operator==(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return std::tie(lhs.recipient(), lhs.mac(), lhs.encryptedSymmetricKey()) ==
         std::tie(rhs.recipient(), rhs.mac(), rhs.encryptedSymmetricKey());
}

bool operator!=(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
