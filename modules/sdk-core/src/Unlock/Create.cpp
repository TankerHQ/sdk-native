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
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
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
UnlockKey ghostDeviceToUnlockKey(GhostDevice const& ghostDevice)
{
  return UnlockKey{
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
  DeviceId deviceId{hash};
  auto const unlockKey = ghostDeviceToUnlockKey(
      GhostDevice{deviceId,
                  deviceKeys.signatureKeyPair.privateKey,
                  deviceKeys.encryptionKeyPair.privateKey});

  return std::make_unique<Registration>(
      Registration{ghostDeviceBlock, unlockKey});
}

GhostDevice extract(UnlockKey const& unlockKey) try
{
  return nlohmann::json::parse(cppcodec::base64_rfc4648::decode(unlockKey))
      .get<GhostDevice>();
}
catch (std::exception const& e)
{
  throw Error::InvalidUnlockKey(e.what());
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
  auto const privateUserEncryptionKey =
      Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
          encryptedUserKey.encryptedPrivateKey, ghostEncryptionKeyPair);
  return BlockGenerator(trustchainId,
                        ghostDevice.privateSignatureKey,
                        ghostDevice.deviceId)
      .addDevice(
          Identity::makeDelegation(userId, ghostDevice.privateSignatureKey),
          deviceKeys.signatureKeyPair.publicKey,
          deviceKeys.encryptionKeyPair.publicKey,
          Crypto::EncryptionKeyPair{encryptedUserKey.publicKey,
                                    privateUserEncryptionKey});
}
}
}
