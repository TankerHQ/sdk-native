#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUserGroup::KeyPublishToUserGroup(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _resourceId(resourceId),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUserGroup::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

ResourceId const& KeyPublishToUserGroup::resourceId() const
{
  return _resourceId;
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
                  lhs.resourceId(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.resourceId(),
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
