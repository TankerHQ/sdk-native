#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>

namespace Tanker
{
struct ProvisionalUserKeys
{
  Crypto::EncryptionKeyPair appKeys;
  Crypto::EncryptionKeyPair tankerKeys;
};
}
