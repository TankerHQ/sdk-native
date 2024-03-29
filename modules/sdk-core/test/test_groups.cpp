#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <catch2/catch_test_macros.hpp>
#include <trompeloeil.hpp>

#include <range/v3/algorithm/find.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

using UsersPullResult = Tanker::Users::IUserAccessor::UserPullResult;

TEST_CASE("Can't create an empty group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const userDevice = user.devices().front();

  TANKER_CHECK_THROWS_WITH_CODE(
      Groups::Manager::makeUserGroupCreationAction({},
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

  auto const action = Groups::Manager::makeUserGroupCreationAction({user, user2},
                                                                   {},
                                                                   groupSignatureKey,
                                                                   groupEncryptionKey,
                                                                   generator.context().id(),
                                                                   userDevice.id(),
                                                                   userDevice.keys().signatureKeyPair.privateKey);

  auto group = action.get<UserGroupCreation::v3>();

  auto const selfSignature = Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey() == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey() == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt(group.sealedPrivateSignatureKey(), groupEncryptionKey) == groupSignatureKey.privateKey);
  REQUIRE(group.members().size() == 2);
  REQUIRE(group.provisionalMembers().size() == 0);
  auto const groupEncryptedKey = ranges::find(group.members(), user.id(), &UserGroupMember2::userId);
  REQUIRE(groupEncryptedKey != group.members().end());
  CHECK(groupEncryptedKey->userPublicKey() == user.userKeys().back().publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(), user.userKeys().back()) ==
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

  auto const action = Groups::Manager::makeUserGroupCreationAction({},
                                                                   {provisionalUser, provisionalUser2},
                                                                   groupSignatureKey,
                                                                   groupEncryptionKey,
                                                                   generator.context().id(),
                                                                   userDevice.id(),
                                                                   userDevice.keys().signatureKeyPair.privateKey);

  auto group = action.get<UserGroupCreation::v3>();

  auto const selfSignature = Crypto::sign(group.signatureData(), groupSignatureKey.privateKey);

  CHECK(group.publicSignatureKey() == groupSignatureKey.publicKey);
  CHECK(group.publicEncryptionKey() == groupEncryptionKey.publicKey);
  CHECK(Crypto::sealDecrypt(group.sealedPrivateSignatureKey(), groupEncryptionKey) == groupSignatureKey.privateKey);
  REQUIRE(group.members().size() == 0);
  REQUIRE(group.provisionalMembers().size() == 2);
  auto const groupEncryptedKey = ranges::find(group.provisionalMembers(),
                                              provisionalUser.appSignatureKeyPair().publicKey,
                                              &UserGroupProvisionalMember3::appPublicSignatureKey);
  REQUIRE(groupEncryptedKey != group.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() == provisionalUser.tankerSignatureKeyPair().publicKey);
  CHECK(Crypto::sealDecrypt(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                                                provisionalUser.tankerEncryptionKeyPair()),
                            provisionalUser.appEncryptionKeyPair()) == groupEncryptionKey.privateKey);
  CHECK(selfSignature == group.selfSignature());
}

TEST_CASE("throws when getting keys of an unknown member")
{
  auto const unknownIdentity = Identity::PublicPermanentIdentity{
      make<Trustchain::TrustchainId>("unknown"),
      make<Trustchain::UserId>("unknown"),
  };

  UserAccessorMock userAccessor;

  REQUIRE_CALL(userAccessor, pull(ANY(std::vector<Trustchain::UserId>)))
      .LR_RETURN(makeCoTask(UsersPullResult{{}, {unknownIdentity.userId}}));

  auto const spublicIdentities = std::vector<SPublicIdentity>{SPublicIdentity{to_string(unknownIdentity)}};
  auto const publicIdentitiesToAdd =
      spublicIdentities | ranges::views::transform(extractPublicIdentity) | ranges::to<std::vector>;
  auto const partitionedIdentitiesToAdd = partitionIdentities(publicIdentitiesToAdd);

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(Groups::Manager::fetchFutureMembers(
          userAccessor,
          Groups::Manager::ProcessedIdentities{spublicIdentities, publicIdentitiesToAdd, partitionedIdentitiesToAdd})),
      Errc::InvalidArgument);
}

TEST_CASE("Fails to add 0 users to a group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");

  auto const userDevice = user.devices().front();

  InternalGroup const group{};

  TANKER_CHECK_THROWS_WITH_CODE(
      Groups::Manager::makeUserGroupAdditionAction(
          {}, {}, group, generator.context().id(), userDevice.id(), userDevice.keys().signatureKeyPair.privateKey),
      Errc::InvalidArgument);
}

TEST_CASE("Can add users to a group")
{
  Test::Generator generator;
  auto const user = generator.makeUser("user");
  auto const user2 = generator.makeUser("user2");

  auto const userDevice = user.devices().front();

  auto const group = user.makeGroup({user2});

  auto const action = Groups::Manager::makeUserGroupAdditionAction({user, user2},
                                                                   {},
                                                                   group,
                                                                   generator.context().id(),
                                                                   userDevice.id(),
                                                                   userDevice.keys().signatureKeyPair.privateKey);

  auto groupAdd = action.get<UserGroupAddition::v3>();

  auto const selfSignature = Crypto::sign(groupAdd.signatureData(), group.currentSigKp().privateKey);

  CHECK(groupAdd.groupId() == Trustchain::GroupId{group.currentSigKp().publicKey});
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash());
  REQUIRE(groupAdd.members().size() == 2);
  REQUIRE(groupAdd.provisionalMembers().size() == 0);

  auto const groupEncryptedKey = ranges::find(groupAdd.members(), user.id(), &UserGroupMember2::userId);
  REQUIRE(groupEncryptedKey != groupAdd.members().end());
  CHECK(groupEncryptedKey->userPublicKey() == user.userKeys().back().publicKey);
  CHECK(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(), user.userKeys().back()) ==
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

  auto const action = Groups::Manager::makeUserGroupAdditionAction({},
                                                                   {provisionalUser, provisionalUser2},
                                                                   group,
                                                                   generator.context().id(),
                                                                   userDevice.id(),
                                                                   userDevice.keys().signatureKeyPair.privateKey);

  auto groupAdd = action.get<UserGroupAddition::v3>();

  auto const selfSignature = Crypto::sign(groupAdd.signatureData(), group.currentSigKp().privateKey);

  CHECK(groupAdd.groupId() == group.id());
  CHECK(groupAdd.previousGroupBlockHash() == group.lastBlockHash());
  REQUIRE(groupAdd.members().size() == 0);
  REQUIRE(groupAdd.provisionalMembers().size() == 2);

  auto const groupEncryptedKey = ranges::find(groupAdd.provisionalMembers(),
                                              provisionalUser.appSignatureKeyPair().publicKey,
                                              &UserGroupProvisionalMember3::appPublicSignatureKey);
  REQUIRE(groupEncryptedKey != groupAdd.provisionalMembers().end());
  CHECK(groupEncryptedKey->tankerPublicSignatureKey() == provisionalUser.tankerSignatureKeyPair().publicKey);
  CHECK(Crypto::sealDecrypt(Crypto::sealDecrypt(groupEncryptedKey->encryptedPrivateEncryptionKey(),
                                                provisionalUser.tankerEncryptionKeyPair()),
                            provisionalUser.appEncryptionKeyPair()) == group.currentEncKp().privateKey);
  CHECK(selfSignature == groupAdd.selfSignature());
}
