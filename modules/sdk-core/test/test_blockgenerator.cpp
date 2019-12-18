#include <doctest.h>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("BlockGenerator")
{
  auto const trustchainId = make<Trustchain::TrustchainId>("trustchain");
  auto const userId = make<Trustchain::UserId>("alice");
  auto const deviceId = make<Trustchain::DeviceId>("alice dev 1");
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

    auto const entry = Serialization::deserialize<ServerEntry>(sblock);
    CHECK_EQ(entry.author().base(), trustchainId.base());
    auto const deviceCreation = entry.action().get_if<DeviceCreation>();
    REQUIRE(deviceCreation != nullptr);
    CHECK(deviceCreation->userId() == userId);
    CHECK(deviceCreation->publicSignatureKey() == mySignKeyPair.publicKey);
    CHECK(deviceCreation->publicEncryptionKey() == encryptionKeyPair.publicKey);
    CHECK(
        Tanker::Crypto::verify(entry.hash(),
                               entry.signature(),
                               deviceCreation->ephemeralPublicSignatureKey()));
    auto const toVerify = deviceCreation->signatureData();
    CHECK(Crypto::verify(toVerify,
                         deviceCreation->delegationSignature(),
                         trustchainKeyPair.publicKey));
  }
}
