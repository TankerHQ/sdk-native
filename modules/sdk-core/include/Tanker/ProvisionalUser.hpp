#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker
{
struct ProvisionalUser
{
  Trustchain::TrustchainId trustchainId;
  Identity::TargetType target;
  std::string value;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
  Crypto::SignatureKeyPair appSignatureKeyPair;
  Crypto::SignatureKeyPair tankerSignatureKeyPair;
};
}
