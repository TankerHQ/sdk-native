#include <Tanker/ProvisionalUsers/PublicUser.hpp>

namespace Tanker::ProvisionalUsers
{
PublicUser::PublicUser(
    Crypto::PublicSignatureKey const& appSignaturePublicKey,
    Crypto::PublicEncryptionKey const& appEncryptionPublicKey,
    Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
    Crypto::PublicEncryptionKey const& tankerEncryptionPublicKey)
  : _appSignaturePublicKey(appSignaturePublicKey),
    _appEncryptionPublicKey(appEncryptionPublicKey),
    _tankerSignaturePublicKey(tankerSignaturePublicKey),
    _tankerEncryptionPublicKey(tankerEncryptionPublicKey)
{
}

Trustchain::ProvisionalUserId PublicUser::id() const
{
  return {_appSignaturePublicKey, _tankerSignaturePublicKey};
}

Crypto::PublicSignatureKey const& PublicUser::appSignaturePublicKey() const
{
  return _appSignaturePublicKey;
}

Crypto::PublicEncryptionKey const& PublicUser::appEncryptionPublicKey() const
{
  return _appEncryptionPublicKey;
}

Crypto::PublicSignatureKey const& PublicUser::tankerSignaturePublicKey() const
{
  return _tankerSignaturePublicKey;
}

Crypto::PublicEncryptionKey const& PublicUser::tankerEncryptionPublicKey() const
{
  return _tankerEncryptionPublicKey;
}

bool operator==(PublicUser const& lhs, PublicUser const& rhs)
{
  return std::tie(lhs.appSignaturePublicKey(),
                  lhs.appEncryptionPublicKey(),
                  lhs.tankerSignaturePublicKey(),
                  lhs.tankerEncryptionPublicKey()) ==
         std::tie(lhs.appSignaturePublicKey(),
                  lhs.appEncryptionPublicKey(),
                  lhs.tankerSignaturePublicKey(),
                  lhs.tankerEncryptionPublicKey());
}
}
