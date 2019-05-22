#pragma once

#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

namespace Tanker
{
struct EncryptedUserKey
{
  Trustchain::DeviceId deviceId;
  Crypto::SealedPrivateEncryptionKey encryptedPrivateKey;
};
}
