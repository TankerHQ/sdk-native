#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>

namespace Tanker
{
struct TankerSecretProvisionalIdentity
{
  Crypto::EncryptionKeyPair encryptionKeyPair;
  Crypto::SignatureKeyPair signatureKeyPair;
};
}
