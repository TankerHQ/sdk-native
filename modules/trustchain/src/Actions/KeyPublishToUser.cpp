#include <Tanker/Trustchain/Actions/KeyPublishToUser.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUser::KeyPublishToUser(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Crypto::Mac const& mac,
    Crypto::SealedSymmetricKey const& sealedSymmetricKey)
  : _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _mac(mac),
    _sealedSymmetricKey(sealedSymmetricKey)
{
}

Crypto::PublicEncryptionKey const&
KeyPublishToUser::recipientPublicEncryptionKey() const
{
  return _recipientPublicEncryptionKey;
}

Crypto::Mac const& KeyPublishToUser::mac() const
{
  return _mac;
}

Crypto::SealedSymmetricKey const& KeyPublishToUser::sealedSymmetricKey() const
{
  return _sealedSymmetricKey;
}

bool operator==(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return std::tie(lhs.recipientPublicEncryptionKey(),
                  lhs.mac(),
                  lhs.sealedSymmetricKey()) ==
         std::tie(rhs.recipientPublicEncryptionKey(),
                  rhs.mac(),
                  rhs.sealedSymmetricKey());
}

bool operator!=(KeyPublishToUser const& lhs, KeyPublishToUser const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
