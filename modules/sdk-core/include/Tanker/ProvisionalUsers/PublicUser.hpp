#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/ProvisionalUserId.hpp>

namespace Tanker::ProvisionalUsers
{
class PublicUser
{
public:
  PublicUser(Crypto::PublicSignatureKey const& appSignaturePublicKey,
             Crypto::PublicEncryptionKey const& appEncryptionPublicKey,
             Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
             Crypto::PublicEncryptionKey const& tankerEncryptionPublicKey);

  Trustchain::ProvisionalUserId id() const;

  Crypto::PublicSignatureKey const& appSignaturePublicKey() const;
  Crypto::PublicEncryptionKey const& appEncryptionPublicKey() const;
  Crypto::PublicSignatureKey const& tankerSignaturePublicKey() const;
  Crypto::PublicEncryptionKey const& tankerEncryptionPublicKey() const;

private:
  Crypto::PublicSignatureKey _appSignaturePublicKey;
  Crypto::PublicEncryptionKey _appEncryptionPublicKey;
  Crypto::PublicSignatureKey _tankerSignaturePublicKey;
  Crypto::PublicEncryptionKey _tankerEncryptionPublicKey;
};

bool operator==(PublicUser const&, PublicUser const&);
bool operator!=(PublicUser const&, PublicUser const&);
}
