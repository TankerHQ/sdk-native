#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

namespace Tanker
{
struct PublicProvisionalUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicEncryptionKey appEncryptionPublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::PublicEncryptionKey tankerEncryptionPublicKey;
};
}
