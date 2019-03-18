#include <doctest.h>

#include <mpark/variant.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Identity/Delegation.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

TEST_CASE("BlockGenerator")
{
  auto const trustchainId = make<TrustchainId>("trustchain");
  auto const userId = make<UserId>("alice");
  auto const deviceId = make<DeviceId>("alice dev 1");
  auto const trustchainKeyPair = Crypto::makeSignatureKeyPair();
  auto const mySignKeyPair = Crypto::makeSignatureKeyPair();
  BlockGenerator blockGenerator(
      trustchainId, mySignKeyPair.privateKey, deviceId);

  SUBCASE("it generates a new user block")
  {
    auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const userEncryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const delegation =
        Identity::makeDelegation(userId, trustchainKeyPair.privateKey);

    auto const sblock = blockGenerator.addUser(delegation,
                                               mySignKeyPair.publicKey,
                                               encryptionKeyPair.publicKey,
                                               userEncryptionKeyPair);

    auto const block = Serialization::deserialize<Block>(sblock);
    CHECK_EQ(block.author, trustchainId);
    auto const entry = blockToUnverifiedEntry(block);
    auto const deviceCreation =
        mpark::get_if<DeviceCreation>(&entry.action.variant());
    REQUIRE(deviceCreation != nullptr);
    CHECK(deviceCreation->userId() == userId);
    CHECK(deviceCreation->publicSignatureKey() == mySignKeyPair.publicKey);
    CHECK(deviceCreation->publicEncryptionKey() == encryptionKeyPair.publicKey);
    CHECK(block.verifySignature(deviceCreation->ephemeralPublicSignatureKey()));
    CHECK(verifyDelegationSignature(*deviceCreation,
                                    trustchainKeyPair.publicKey));
  }
}
