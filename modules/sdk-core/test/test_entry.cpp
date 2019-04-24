#include <doctest.h>

#include <Tanker/Block.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("blockToUnverifiedEntry")
{
  auto const trustchainId = make<Trustchain::TrustchainId>("trustchain");
  auto const userId = make<Trustchain::UserId>("alice");
  auto const deviceId = make<Trustchain::DeviceId>("alice dev 1");
  auto const trustchainKeyPair = Crypto::makeSignatureKeyPair();
  auto const mySignKeyPair = Crypto::makeSignatureKeyPair();

  BlockGenerator blockGenerator(
      trustchainId, mySignKeyPair.privateKey, deviceId);

  auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
  auto const userEncryptionKeyPair = Crypto::makeEncryptionKeyPair();
  auto const delegation =
      Identity::makeDelegation(userId, trustchainKeyPair.privateKey);

  auto const sblock = blockGenerator.addUser(delegation,
                                             mySignKeyPair.publicKey,
                                             encryptionKeyPair.publicKey,
                                             userEncryptionKeyPair);

  auto const block = Serialization::deserialize<Block>(sblock);

  UnverifiedEntry entry = blockToUnverifiedEntry(block);

  CHECK(entry.index == block.index);
  CHECK(entry.nature == block.nature);
  CHECK(entry.author == block.author);
  CHECK(entry.signature == block.signature);
  CHECK(entry.action.holdsAlternative<DeviceCreation>());
}
