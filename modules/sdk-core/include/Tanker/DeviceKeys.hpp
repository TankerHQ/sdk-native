#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>

namespace Tanker
{
struct DeviceKeys
{
  Crypto::SignatureKeyPair signatureKeyPair;
  Crypto::EncryptionKeyPair encryptionKeyPair;
  DeviceId deviceId;

  static DeviceKeys create();
};
}
