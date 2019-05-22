#include <Tanker/Unlock/Create.hpp>

#include <Tanker/Block.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
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

std::unique_ptr<Registration> generate(
    UserId const& userId,
    Crypto::EncryptionKeyPair const& userKeypair,
    BlockGenerator const& blockGen,
    DeviceKeys const& deviceKeys)
{
  auto const ghostDeviceBlock = blockGen.addGhostDevice(
      Identity::makeDelegation(userId, blockGen.signatureKey()),
      deviceKeys.signatureKeyPair.publicKey,
      deviceKeys.encryptionKeyPair.publicKey,
      userKeypair);

  auto const hash = Serialization::deserialize<Block>(ghostDeviceBlock).hash();
  Trustchain::DeviceId deviceId{hash};
  auto const verificationKey = ghostDeviceToVerificationKey(
      GhostDevice{deviceKeys.signatureKeyPair.privateKey,
                  deviceKeys.encryptionKeyPair.privateKey});

  return std::make_unique<Registration>(
      Registration{ghostDeviceBlock, verificationKey});
}

std::vector<uint8_t> createValidatedDevice(
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
  return BlockGenerator(trustchainId,
                        ghostDevice.privateSignatureKey,
                        encryptedUserKey.deviceId)
      .addDevice(
          Identity::makeDelegation(userId, ghostDevice.privateSignatureKey),
          deviceKeys.signatureKeyPair.publicKey,
          deviceKeys.encryptionKeyPair.publicKey,
          Crypto::makeEncryptionKeyPair(privateUserEncryptionKey));
}
}
}
