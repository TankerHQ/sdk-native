#include <Tanker/Revocation.hpp>

#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>
#include <Helpers/TransformTo.hpp>

#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Errors;

TEST_CASE("Revocation tests")
{
  Test::Generator generator;

  UserAccessorMock userAccessorMock;

  SUBCASE(
      "getUserFromUserId throws if userId does not have a user key (user V1)")
  {
    auto const alice = generator.makeUser("alice");
    auto const brokenAlice = Users::User(alice.id(), {}, {});
    REQUIRE_CALL(userAccessorMock, pull(std::vector{alice.id()}))
        .RETURN(
            makeCoTask(Users::IUserAccessor::PullResult{{brokenAlice}, {}}));
    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Revocation::getUserFromUserId(alice.id(), userAccessorMock)),
        Errc::InternalError);
  }

  SUBCASE("getUserFromUserId correctly finds bob user")
  {
    auto alice = generator.makeUser("alice");
    REQUIRE_CALL(userAccessorMock, pull(std::vector{alice.id()}))
        .RETURN(makeCoTask(Users::IUserAccessor::PullResult{{alice}, {}}));
    auto const user =
        AWAIT(Revocation::getUserFromUserId(alice.id(), userAccessorMock));
    CHECK_EQ(*user.userKey(), alice.userKeys().back().publicKey);
  }

  SUBCASE("devicePrivateKey can be encrypted & decrypted")
  {
    auto bob = generator.makeUser("bob");
    bob.addDevice();
    auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const encryptedPrivateKeys = Revocation::encryptPrivateKeyForDevices(
        Test::transformTo<std::vector<Users::Device>>(bob.devices()),
        bob.devices().front().id(),
        encryptionKeyPair.privateKey);

    REQUIRE_EQ(encryptedPrivateKeys.size(), 1);

    auto const decryptedPrivateKey = Revocation::decryptPrivateKeyForDevice(
        bob.devices().back().keys(), encryptedPrivateKeys[0].second);

    CHECK_EQ(decryptedPrivateKey, encryptionKeyPair.privateKey);
  }
}
