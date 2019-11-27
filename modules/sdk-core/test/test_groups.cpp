#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

TEST_CASE("Can't create an empty group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");

  auto const user = *builder.findUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  TANKER_CHECK_THROWS_WITH_CODE(
      Groups::Manager::generateCreateGroupBlock(
          {}, {}, userBlockGenerator, groupSignatureKey, groupEncryptionKey),
      Errc::InvalidArgument);
}

TEST_CASE("Can create a group with two users")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  builder.makeUser3("user2");

  auto const user = *builder.findUser("user");
  auto const user2 = *builder.findUser("user2");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const preserializedBlock = Groups::Manager::generateCreateGroupBlock(
      {user.asTankerUser(), user2.asTankerUser()},
      {},
      userBlockGenerator,
      groupSignatureKey,
      groupEncryptionKey);

  auto block =
      Serialization::deserialize<Trustchain::Block>(preserializedBlock);
  auto entry = blockToServerEntry(block);
  auto group =
      entry.action().get<UserGroupCreation>().get<UserGroupCreation::v2>();

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
                     return groupEncryptedKey.userId() == user.userId;
                   });
  REQUIRE(groupEncryptedKey != group.members().end());
  CHECK(groupEncryptedKey->userPublicKey() ==
        user.userKeys.back().keyPair.publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                            user.userKeys.back().keyPair) ==
        groupEncryptionKey.privateKey);
  CHECK(selfSignature == group.selfSignature());
}

TEST_CASE("Can create a group with two provisional users")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  auto const user = *builder.findUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto const provisionalUser = builder.makeProvisionalUser("bob@tanker");
  auto const provisionalUser2 = builder.makeProvisionalUser("charlie@tanker");

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const preserializedBlock = Groups::Manager::generateCreateGroupBlock(
      {},
      {provisionalUser.publicProvisionalUser,
       provisionalUser2.publicProvisionalUser},
      userBlockGenerator,
      groupSignatureKey,
      groupEncryptionKey);

  auto block =
      Serialization::deserialize<Trustchain::Block>(preserializedBlock);
  auto entry = blockToServerEntry(block);
  auto group =
      entry.action().get<UserGroupCreation>().get<UserGroupCreation::v2>();

  auto const selfSignature =
      Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey() == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey() == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt(group.sealedPrivateSignatureKey(),
                            groupEncryptionKey) ==
        groupSignatureKey.privateKey);
  REQUIRE(group.members().size() == 0);
  REQUIRE(group.provisionalMembers().size() == 2);
  auto const groupEncryptedKey = std::find_if(
      group.provisionalMembers().begin(),
      group.provisionalMembers().end(),
      [&](auto const& groupEncryptedKey) {
        return groupEncryptedKey.appPublicSignatureKey() ==
               provisionalUser.publicProvisionalUser.appSignaturePublicKey;
      });
  REQUIRE(groupEncryptedKey != group.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() ==
        provisionalUser.publicProvisionalUser.tankerSignaturePublicKey);
  CHECK(Crypto::sealDecrypt(
            Crypto::sealDecrypt(
                groupEncryptedKey->encryptedPrivateEncryptionKey(),
                provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair),
            provisionalUser.secretProvisionalUser.appEncryptionKeyPair) ==
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

  REQUIRE_CALL(userAccessor, pull(trompeloeil::_))
      .LR_RETURN(
          makeCoTask(UserAccessor::PullResult{{}, {unknownIdentity.userId}}));

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(Groups::Manager::fetchFutureMembers(
          userAccessor, {SPublicIdentity{to_string(unknownIdentity)}})),
      Errc::InvalidArgument);
}

TEST_CASE("Fails to add 0 users to a group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");

  auto const user = *builder.findUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  InternalGroup const group{};

  TANKER_CHECK_THROWS_WITH_CODE(Groups::Manager::generateAddUserToGroupBlock(
                                    {}, {}, userBlockGenerator, group),
                                Errc::InvalidArgument);
}

TEST_CASE("Can add users to a group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  builder.makeUser3("user2");

  auto const user = *builder.findUser("user");
  auto const user2 = *builder.findUser("user2");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto const groupResult = builder.makeGroup(userDevice, {user, user2});
  auto group = groupResult.group.tankerGroup;

  auto const preserializedBlock = Groups::Manager::generateAddUserToGroupBlock(
      {user.asTankerUser(), user2.asTankerUser()},
      {},
      userBlockGenerator,
      group);

  auto block =
      Serialization::deserialize<Trustchain::Block>(preserializedBlock);
  auto entry = blockToServerEntry(block);
  auto groupAdd =
      entry.action().get<UserGroupAddition>().get<UserGroupAddition::v2>();

  auto const selfSignature =
      Crypto::sign(groupAdd.signatureData(), group.signatureKeyPair.privateKey);

  CHECK(groupAdd.groupId() ==
        Trustchain::GroupId{group.signatureKeyPair.publicKey});
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash);
  REQUIRE(groupAdd.members().size() == 2);
  REQUIRE(groupAdd.provisionalMembers().size() == 0);

  auto const groupEncryptedKey =
      std::find_if(groupAdd.members().begin(),
                   groupAdd.members().end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.userId() == user.userId;
                   });
  REQUIRE(groupEncryptedKey != groupAdd.members().end());
  CHECK(groupEncryptedKey->userPublicKey() ==
        user.userKeys.back().keyPair.publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                            user.userKeys.back().keyPair) ==
        group.encryptionKeyPair.privateKey);
  CHECK(selfSignature == groupAdd.selfSignature());
}

TEST_CASE("Can add provisional users to a group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  auto const user = *builder.findUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto const groupResult = builder.makeGroup(userDevice, {user});
  auto group = groupResult.group.tankerGroup;

  auto const provisionalUser = builder.makeProvisionalUser("bob@tanker");
  auto const provisionalUser2 = builder.makeProvisionalUser("charlie@tanker");

  auto const preserializedBlock = Groups::Manager::generateAddUserToGroupBlock(
      {},
      {provisionalUser.publicProvisionalUser,
       provisionalUser2.publicProvisionalUser},
      userBlockGenerator,
      group);

  auto block =
      Serialization::deserialize<Trustchain::Block>(preserializedBlock);
  auto entry = blockToServerEntry(block);
  auto groupAdd =
      entry.action().get<UserGroupAddition>().get<UserGroupAddition::v2>();

  auto const selfSignature =
      Crypto::sign(groupAdd.signatureData(), group.signatureKeyPair.privateKey);

  CHECK(groupAdd.groupId() ==
        Trustchain::GroupId{group.signatureKeyPair.publicKey});
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash);
  REQUIRE(groupAdd.members().size() == 0);
  REQUIRE(groupAdd.provisionalMembers().size() == 2);

  auto const groupEncryptedKey = std::find_if(
      groupAdd.provisionalMembers().begin(),
      groupAdd.provisionalMembers().end(),
      [&](auto const& groupEncryptedKey) {
        return groupEncryptedKey.appPublicSignatureKey() ==
               provisionalUser.publicProvisionalUser.appSignaturePublicKey;
      });
  REQUIRE(groupEncryptedKey != groupAdd.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() ==
        provisionalUser.publicProvisionalUser.tankerSignaturePublicKey);
  CHECK(Crypto::sealDecrypt(
            Crypto::sealDecrypt(
                groupEncryptedKey->encryptedPrivateEncryptionKey(),
                provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair),
            provisionalUser.secretProvisionalUser.appEncryptionKeyPair) ==
        group.encryptionKeyPair.privateKey);
  CHECK(selfSignature == groupAdd.selfSignature());
}
