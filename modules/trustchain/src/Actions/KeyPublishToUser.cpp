#include <Tanker/Trustchain/Actions/KeyPublishToUser.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUser::KeyPublishToUser(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _resourceId(resourceId),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUser::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

ResourceId const& KeyPublishToUser::resourceId() const
{
  return _resourceId;
}

Crypto::SealedSymmetricKey const& KeyPublishToUser::sealedSymmetricKey() const
{
  return _sealedSymmetricKey;
}

bool operator==(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return std::tie(lhs.recipientPublicEncryptionKey(),
                  lhs.resourceId(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.resourceId(),
                  rhs.sealedSymmetricKey());
}

bool operator!=(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
