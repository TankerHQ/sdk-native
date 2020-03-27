#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Entries.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "TestVerifier.hpp"
#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>
#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

using UsersPullResult = Tanker::Users::IUserAccessor::PullResult;

TEST_CASE("Can't create an empty group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const userDevice = user.devices().front();

  TANKER_CHECK_THROWS_WITH_CODE(
      Groups::Manager::makeUserGroupCreationEntry(
          {},
          {},
          Crypto::makeSignatureKeyPair(),
          Crypto::makeEncryptionKeyPair(),
          generator.context().id(),
          userDevice.id(),
          userDevice.keys().signatureKeyPair.privateKey),
      Errc::InvalidArgument);
}

TEST_CASE("Can create a group with two users")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const user2 = generator.makeUser("user2");

  auto const userDevice = user.devices().front();

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const clientEntry = Groups::Manager::makeUserGroupCreationEntry(
      {user, user2},
      {},
      groupSignatureKey,
      groupEncryptionKey,
      generator.context().id(),
      userDevice.id(),
      userDevice.keys().signatureKeyPair.privateKey);

  auto const serverEntry = clientToServerEntry(clientEntry);
  auto group = serverEntry.action()
                   .get<UserGroupCreation>()
                   .get<UserGroupCreation::v2>();

  auto const selfSignature =
      Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey() == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey() == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt(group.sealedPrivateSignatureKey(),
                            groupEncryptionKey) ==
        groupSignatureKey.privateKey);
  REQUIRE(group.members().size() == 2);
  REQUIRE(group.provisionalMembers().size() == 0);
  auto const groupEncryptedKey =
      std::find_if(group.members().begin(),
                   group.members().end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.userId() == user.id();
                   });
  REQUIRE(groupEncryptedKey != group.members().end());
  CHECK(groupEncryptedKey->userPublicKey() == user.userKeys().back().publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                            user.userKeys().back()) ==
        groupEncryptionKey.privateKey);
  CHECK(selfSignature == group.selfSignature());
}

TEST_CASE("Can create a group with two provisional users")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const userDevice = user.devices().front();

  auto const provisionalUser = generator.makeProvisionalUser("bob@tanker");
  auto const provisionalUser2 = generator.makeProvisionalUser("charlie@tanker");

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const clientEntry = Groups::Manager::makeUserGroupCreationEntry(
      {},
      {provisionalUser, provisionalUser2},
      groupSignatureKey,
      groupEncryptionKey,
      generator.context().id(),
      userDevice.id(),
      userDevice.keys().signatureKeyPair.privateKey);

  auto const serverEntry = clientToServerEntry(clientEntry);
  auto group = serverEntry.action()
                   .get<UserGroupCreation>()
                   .get<UserGroupCreation::v2>();

  auto const selfSignature =
      Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey() == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey() == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt(group.sealedPrivateSignatureKey(),
                            groupEncryptionKey) ==
        groupSignatureKey.privateKey);
  REQUIRE(group.members().size() == 0);
  REQUIRE(group.provisionalMembers().size() == 2);
  auto const groupEncryptedKey =
      std::find_if(group.provisionalMembers().begin(),
                   group.provisionalMembers().end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.appPublicSignatureKey() ==
                            provisionalUser.appSignatureKeyPair().publicKey;
                   });
  REQUIRE(groupEncryptedKey != group.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() ==
        provisionalUser.tankerSignatureKeyPair().publicKey);
  CHECK(Crypto::sealDecrypt(
            Crypto::sealDecrypt(
                groupEncryptedKey->encryptedPrivateEncryptionKey(),
                provisionalUser.tankerEncryptionKeyPair()),
            provisionalUser.appEncryptionKeyPair()) ==
        groupEncryptionKey.privateKey);
  CHECK(selfSignature == group.selfSignature());
}

TEST_CASE("throws when getting keys of an unknown member")
{
  auto const unknownIdentity = Identity::PublicPermanentIdentity{
      make<Trustchain::TrustchainId>("unknown"),
      make<Trustchain::UserId>("unknown"),
  };

  UserAccessorMock userAccessor;

  REQUIRE_CALL(userAccessor, pull(ANY(gsl::span<Trustchain::UserId const>)))
      .LR_RETURN(makeCoTask(UsersPullResult{{}, {unknownIdentity.userId}}));

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(Groups::Manager::fetchFutureMembers(
          userAccessor, {SPublicIdentity{to_string(unknownIdentity)}})),
      Errc::InvalidArgument);
}

TEST_CASE("Fails to add 0 users to a group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");

  auto const userDevice = user.devices().front();

  InternalGroup const group{};

  TANKER_CHECK_THROWS_WITH_CODE(
      Groups::Manager::makeUserGroupAdditionEntry(
          {},
          {},
          group,
          generator.context().id(),
          userDevice.id(),
          userDevice.keys().signatureKeyPair.privateKey),
      Errc::InvalidArgument);
}

TEST_CASE("Can add users to a group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const user2 = generator.makeUser("user2");

  auto const userDevice = user.devices().front();

  auto const group = user.makeGroup({user2});

  auto const clientEntry = Groups::Manager::makeUserGroupAdditionEntry(
      {user, user2},
      {},
      group,
      generator.context().id(),
      userDevice.id(),
      userDevice.keys().signatureKeyPair.privateKey);

  auto const serverEntry = clientToServerEntry(clientEntry);
  auto groupAdd = serverEntry.action()
                      .get<UserGroupAddition>()
                      .get<UserGroupAddition::v2>();

  auto const selfSignature =
      Crypto::sign(groupAdd.signatureData(), group.currentSigKp().privateKey);

  CHECK(groupAdd.groupId() ==
        Trustchain::GroupId{group.currentSigKp().publicKey});
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash());
  REQUIRE(groupAdd.members().size() == 2);
  REQUIRE(groupAdd.provisionalMembers().size() == 0);

  auto const groupEncryptedKey =
      std::find_if(groupAdd.members().begin(),
                   groupAdd.members().end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.userId() == user.id();
                   });
  REQUIRE(groupEncryptedKey != groupAdd.members().end());
  CHECK(groupEncryptedKey->userPublicKey() == user.userKeys().back().publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                            user.userKeys().back()) ==
        group.currentEncKp().privateKey);
  CHECK(selfSignature == groupAdd.selfSignature());
}

TEST_CASE("Can add provisional users to a group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const userDevice = user.devices().front();

  auto const group = user.makeGroup({});

  auto const provisionalUser = generator.makeProvisionalUser("bob@tanker");
  auto const provisionalUser2 = generator.makeProvisionalUser("charlie@tanker");

  auto const clientEntry = Groups::Manager::makeUserGroupAdditionEntry(
      {},
      {provisionalUser, provisionalUser2},
      group,
      generator.context().id(),
      userDevice.id(),
      userDevice.keys().signatureKeyPair.privateKey);

  auto const serverEntry = clientToServerEntry(clientEntry);
  auto groupAdd = serverEntry.action()
                      .get<UserGroupAddition>()
                      .get<UserGroupAddition::v2>();

  auto const selfSignature =
      Crypto::sign(groupAdd.signatureData(), group.currentSigKp().privateKey);

  CHECK(groupAdd.groupId() == group.id());
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash());
  REQUIRE(groupAdd.members().size() == 0);
  REQUIRE(groupAdd.provisionalMembers().size() == 2);

  auto const groupEncryptedKey =
      std::find_if(groupAdd.provisionalMembers().begin(),
                   groupAdd.provisionalMembers().end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.appPublicSignatureKey() ==
                            provisionalUser.appSignatureKeyPair().publicKey;
                   });
  REQUIRE(groupEncryptedKey != groupAdd.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() ==
        provisionalUser.tankerSignatureKeyPair().publicKey);
  CHECK(Crypto::sealDecrypt(
            Crypto::sealDecrypt(
                groupEncryptedKey->encryptedPrivateEncryptionKey(),
                provisionalUser.tankerEncryptionKeyPair()),
            provisionalUser.appEncryptionKeyPair()) ==
        group.currentEncKp().privateKey);
  CHECK(selfSignature == groupAdd.selfSignature());
}
