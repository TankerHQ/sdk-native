#include <Tanker/Unlock/Create.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Registration.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <stdexcept>

namespace Tanker
{
using Trustchain::UserId;

namespace Unlock
{
VerificationKey ghostDeviceToVerificationKey(GhostDevice const& ghostDevice)
{
  return VerificationKey{
      cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};
}

VerificationKey generate(UserId const& userId,
                         Crypto::EncryptionKeyPair const& userKeypair,
                         BlockGenerator const& blockGen,
                         DeviceKeys const& deviceKeys)
{
  return ghostDeviceToVerificationKey(
      GhostDevice{deviceKeys.signatureKeyPair.privateKey,
                  deviceKeys.encryptionKeyPair.privateKey});
}

Trustchain::Block createValidatedDevice(
    Trustchain::TrustchainId const& trustchainId,
    UserId const& userId,
    GhostDevice const& ghostDevice,
    DeviceKeys const& deviceKeys,
    EncryptedUserKey const& encryptedUserKey)
{
  auto const ghostEncryptionKeyPair =
      makeEncryptionKeyPair(ghostDevice.privateEncryptionKey);

  auto const privateUserEncryptionKey = Crypto::sealDecrypt(
      encryptedUserKey.encryptedPrivateKey, ghostEncryptionKeyPair);

  return Serialization::deserialize<Trustchain::Block>(
      BlockGenerator(trustchainId, {}, encryptedUserKey.deviceId)
          .addDevice(
              Identity::makeDelegation(userId, ghostDevice.privateSignatureKey),
              deviceKeys.signatureKeyPair.publicKey,
              deviceKeys.encryptionKeyPair.publicKey,
              Crypto::makeEncryptionKeyPair(privateUserEncryptionKey)));
}
}
}
