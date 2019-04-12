#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>

namespace Tanker
{
struct EncryptedUserKey
{
  Crypto::PublicEncryptionKey publicKey;
  Crypto::SealedPrivateEncryptionKey encryptedPrivateKey;
};
}
