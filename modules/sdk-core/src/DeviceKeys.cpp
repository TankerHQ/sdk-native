#include <Tanker/DeviceKeys.hpp>

#include <Tanker/Crypto/Crypto.hpp>

namespace Tanker
{

DeviceKeys DeviceKeys::create()
{
  return DeviceKeys{Crypto::makeSignatureKeyPair(),
                    Crypto::makeEncryptionKeyPair()};
}

DeviceKeys DeviceKeys::create(Crypto::PrivateSignatureKey const& sigKey,
                              Crypto::PrivateEncryptionKey const& encKey)
{
  return DeviceKeys{Crypto::makeSignatureKeyPair(sigKey),
                    Crypto::makeEncryptionKeyPair(encKey)};
}
}
