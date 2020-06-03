#include <Tanker/Errors/Errc.hpp>
#include <Tanker/ProvisionalUsers/Updater.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include <doctest.h>

#include "LocalUserAccessorMock.hpp"
#include "TestVerifier.hpp"
#include "TrustchainGenerator.hpp"

using namespace Tanker;
using namespace Tanker::Errors;

TEST_CASE("Preregistration")
{
  Test::Generator generator;
  LocalUserAccessorMock userLocalAccessor;

  auto const alice = generator.makeUser("alice");
  auto const provisionalUser = generator.makeProvisionalUser("alice@email.com");
  auto picEntry = alice.claim(provisionalUser);

  SUBCASE("throws if the user key is not found")
  {
    REQUIRE_CALL(userLocalAccessor,
                 pullUserKeyPair(alice.userKeys().back().publicKey))
        .RETURN(
            makeCoTask(std::optional<Crypto::EncryptionKeyPair>(std::nullopt)));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(ProvisionalUsers::Updater::extractKeysToStore(
            userLocalAccessor, picEntry)),
        Errc::InternalError);
  }

  SUBCASE("can decrypt a preregistration claim")
  {
    REQUIRE_CALL(userLocalAccessor,
                 pullUserKeyPair(alice.userKeys().back().publicKey))
        .RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));

    auto const gotKeys = AWAIT(ProvisionalUsers::Updater::extractKeysToStore(
        userLocalAccessor, picEntry));
    CHECK_EQ(gotKeys.appSignaturePublicKey,
             provisionalUser.appSignatureKeyPair().publicKey);
    CHECK_EQ(gotKeys.tankerSignaturePublicKey,
             provisionalUser.tankerSignatureKeyPair().publicKey);
    CHECK_EQ(gotKeys.appEncryptionKeyPair,
             provisionalUser.appEncryptionKeyPair());
    CHECK_EQ(gotKeys.tankerEncryptionKeyPair,
             provisionalUser.tankerEncryptionKeyPair());
  }
}
