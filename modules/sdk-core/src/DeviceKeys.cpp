#include <Tanker/DeviceKeys.hpp>

#include <Tanker/Crypto/Crypto.hpp>

namespace Tanker
{
DeviceKeys DeviceKeys::create()
{
  return DeviceKeys{
      Crypto::makeSignatureKeyPair(), Crypto::makeEncryptionKeyPair(), {}};
}
}
