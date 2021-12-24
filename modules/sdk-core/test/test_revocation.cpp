#include <Tanker/Revocation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include <range/v3/range/conversion.hpp>

#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <catch2/catch.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

TEST_CASE("Revocation tests")
{
  Test::Generator generator;

  UserAccessorMock userAccessorMock;

  SECTION(
      "getUserFromUserId throws if userId does not have a user key (user V1)")
  {
    auto const alice = generator.makeUser("alice");
    auto const brokenAlice = Users::User(alice.id(), {}, {});
    REQUIRE_CALL(userAccessorMock,
                 pull(std::vector{alice.id()}, Users::IRequester::IsLight::No))
        .RETURN(makeCoTask(
            Users::IUserAccessor::UserPullResult{{brokenAlice}, {}}));
    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Revocation::getUserFromUserId(alice.id(), userAccessorMock)),
        Errc::InternalError);
  }

  SECTION("getUserFromUserId correctly finds bob user")
  {
    auto alice = generator.makeUser("alice");
    REQUIRE_CALL(userAccessorMock,
                 pull(std::vector{alice.id()}, Users::IRequester::IsLight::No))
        .RETURN(makeCoTask(Users::IUserAccessor::UserPullResult{{alice}, {}}));
    auto const user =
        AWAIT(Revocation::getUserFromUserId(alice.id(), userAccessorMock));
    CHECK(*user.userKey() == alice.userKeys().back().publicKey);
  }

  SECTION("devicePrivateKey can be encrypted & decrypted")
  {
    auto bob = generator.makeUser("bob");
    bob.addDevice();
    auto const encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const encryptedPrivateKeys = Revocation::encryptPrivateKeyForDevices(
        bob.devices() | ranges::to<std::vector<Users::Device>>,
        bob.devices().front().id(),
        encryptionKeyPair.privateKey);

    REQUIRE(encryptedPrivateKeys.size() == 1);

    auto const decryptedPrivateKey = Revocation::decryptPrivateKeyForDevice(
        bob.devices().back().keys(), encryptedPrivateKeys[0].second);

    CHECK(decryptedPrivateKey == encryptionKeyPair.privateKey);
  }
}
