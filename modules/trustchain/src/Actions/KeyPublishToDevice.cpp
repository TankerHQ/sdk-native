#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToDevice::KeyPublishToDevice(DeviceId const& recipient,
                                       ResourceId const& resourceId,
                                       Crypto::EncryptedSymmetricKey const& key)
  : _recipient(recipient), _resourceId(resourceId), _key(key)
{
}

DeviceId const& KeyPublishToDevice::recipient() const
{
  return _recipient;
}

ResourceId const& KeyPublishToDevice::resourceId() const
{
  return _resourceId;
}

Crypto::EncryptedSymmetricKey const& KeyPublishToDevice::encryptedSymmetricKey()
    const
{
  return _key;
}

bool operator==(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return std::tie(
             lhs.recipient(), lhs.resourceId(), lhs.encryptedSymmetricKey()) ==
         std::tie(
             rhs.recipient(), rhs.resourceId(), rhs.encryptedSymmetricKey());
}

bool operator!=(KeyPublishToDevice const& lhs, KeyPublishToDevice const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
