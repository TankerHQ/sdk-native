#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/UserNotFound.hpp>

#include <Helpers/Await.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

#include <mockaron/mockaron.hpp>

#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

TEST_CASE("Can't create an empty group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");

  auto const user = *builder.getUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  CHECK_THROWS_AS(
      AWAIT(Groups::Manager::generateCreateGroupBlock(
          {}, userBlockGenerator, groupSignatureKey, groupEncryptionKey)),
      Error::InvalidGroupSize);
}

TEST_CASE("Can create a group with two users")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  builder.makeUser3("user2");

  auto const user = *builder.getUser("user");
  auto const user2 = *builder.getUser("user2");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const preserializedBlock =
      AWAIT(Groups::Manager::generateCreateGroupBlock(
          {user.userKeys.back().keyPair.publicKey,
           user2.userKeys.back().keyPair.publicKey},
          userBlockGenerator,
          groupSignatureKey,
          groupEncryptionKey));

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  auto entry = blockToUnverifiedEntry(block);
  auto group = mpark::get<UserGroupCreation>(entry.action.variant());

  auto const selfSignature =
      Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt<Crypto::PrivateSignatureKey>(
            group.encryptedPrivateSignatureKey, groupEncryptionKey) ==
        groupSignatureKey.privateKey);
  REQUIRE(group.encryptedGroupPrivateEncryptionKeysForUsers.size() == 2);
  auto const groupEncryptedKey =
      std::find_if(group.encryptedGroupPrivateEncryptionKeysForUsers.begin(),
                   group.encryptedGroupPrivateEncryptionKeysForUsers.end(),
                   [&](auto const& groupEncryptedKey) {
                     return groupEncryptedKey.publicUserEncryptionKey ==
                            user.userKeys.back().keyPair.publicKey;
                   });
  CHECK(Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
            groupEncryptedKey->encryptedGroupPrivateEncryptionKey,
            user.userKeys.back().keyPair) == groupEncryptionKey.privateKey);
  CHECK(selfSignature == group.selfSignature);
}

TEST_CASE("throws when getting keys of an unknown member")
{
  auto const unknownUid = make<Trustchain::UserId>("unknown");

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;

  REQUIRE_CALL(
      userAccessor.get_mock_impl(),
      pull(trompeloeil::eq(gsl::span<Trustchain::UserId const>{unknownUid})))
      .LR_RETURN((UserAccessor::PullResult{{}, {unknownUid}}));

  REQUIRE_THROWS_AS(
      AWAIT(Groups::Manager::getMemberKeys(userAccessor.get(), {unknownUid})),
      Error::UserNotFound);
}

TEST_CASE("Fails to add 0 users to a group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");

  auto const user = *builder.getUser("user");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  Group const group{};

  CHECK_THROWS_AS(AWAIT(Groups::Manager::generateAddUserToGroupBlock(
                      {}, userBlockGenerator, group)),
                  Error::InvalidGroupSize);
}

TEST_CASE("Can add users to a group")
{
  TrustchainBuilder builder;
  builder.makeUser3("user");
  builder.makeUser3("user2");

  auto const user = *builder.getUser("user");
  auto const user2 = *builder.getUser("user2");
  auto const userDevice = user.devices.front();
  auto const userBlockGenerator = builder.makeBlockGenerator(userDevice);

  auto const groupResult = builder.makeGroup(userDevice, {user, user2});
  auto group = groupResult.group.tankerGroup;

  auto const preserializedBlock =
      AWAIT(Groups::Manager::generateAddUserToGroupBlock(
          {user.userKeys.back().keyPair.publicKey,
           user2.userKeys.back().keyPair.publicKey},
          userBlockGenerator,
          group));

  auto block = Serialization::deserialize<Block>(preserializedBlock);
  auto entry = blockToUnverifiedEntry(block);
  auto groupAdd = mpark::get<UserGroupAddition>(entry.action.variant());

  auto const selfSignature =
      Crypto::sign(groupAdd.signatureData(), group.signatureKeyPair.privateKey);

  CHECK(groupAdd.groupId == GroupId{group.signatureKeyPair.publicKey});
  CHECK(groupAdd.previousGroupBlock == group.lastBlockHash);
  REQUIRE(groupAdd.encryptedGroupPrivateEncryptionKeysForUsers.size() == 2);

  auto const groupEncryptedKey =
      std::find_if(groupAdd.encryptedGroupPrivateEncryptionKeysForUsers.begin(),
                   groupAdd.encryptedGroupPrivateEncryptionKeysForUsers.end(),
                   [&](auto const& encryptedKey) {
                     return encryptedKey.publicUserEncryptionKey ==
                            user.userKeys.back().keyPair.publicKey;
                   });
  REQUIRE(groupEncryptedKey !=
          groupAdd.encryptedGroupPrivateEncryptionKeysForUsers.end());

  CHECK(Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
            groupEncryptedKey->encryptedGroupPrivateEncryptionKey,
            user.userKeys.back().keyPair) ==
        group.encryptionKeyPair.privateKey);
  CHECK(selfSignature == groupAdd.selfSignatureWithCurrentKey);
}
