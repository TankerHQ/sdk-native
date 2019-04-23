#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUserGroup::KeyPublishToUserGroup(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Crypto::Mac const& mac,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _mac(mac),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUserGroup::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

Crypto::Mac const& KeyPublishToUserGroup::mac() const
{
  return _mac;
}

Crypto::SealedSymmetricKey const& KeyPublishToUserGroup::sealedSymmetricKey()
    const
{
  return _sealedSymmetricKey;
}

bool operator==(KeyPublishToUserGroup const& lhs,
                KeyPublishToUserGroup const& rhs)
{
  return std::tie(lhs.recipientPublicEncryptionKey(),
                  lhs.mac(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.mac(),
                  rhs.sealedSymmetricKey());
}

bool operator!=(KeyPublishToUserGroup const& lhs,
                KeyPublishToUserGroup const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
