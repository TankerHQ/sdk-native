#include <Tanker/Unlock/Create.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <stdexcept>

namespace Tanker::Unlock
{
using Trustchain::UserId;

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
