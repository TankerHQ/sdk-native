#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>

namespace Tanker
{
struct DeviceKeys
{
  Crypto::SignatureKeyPair signatureKeyPair;
  Crypto::EncryptionKeyPair encryptionKeyPair;

  static DeviceKeys create();
  static DeviceKeys create(Crypto::PrivateSignatureKey const&,
                           Crypto::PrivateEncryptionKey const&);
};
}
