#pragma once

#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Types.hpp>

namespace Tanker
{
struct EncryptedUserKey
{
  Crypto::PublicEncryptionKey publicKey;
  Crypto::SealedPrivateEncryptionKey encryptedPrivateKey;
};
}
