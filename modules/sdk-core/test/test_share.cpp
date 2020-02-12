#include <Tanker/Share.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "GroupAccessorMock.hpp"
#include "MockConnection.hpp"
#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;
using namespace Tanker::Errors;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace
{
template <typename T>
bool hasDevice(gsl::span<Users::Device const> devices,
               Crypto::BasicHash<T> const& hash)
{
  return std::find_if(devices.begin(), devices.end(), [&](auto const& device) {
           return device.id.base() == hash.base();
         }) != devices.end();
}

template <typename U = void, typename T = U>
void assertEqual(std::vector<T> aa, std::vector<U> bb)
{
  std::sort(aa.begin(), aa.end());
  std::sort(bb.begin(), bb.end());

  CAPTURE(aa);
  CAPTURE(bb);
  CHECK(std::equal(aa.begin(), aa.end(), bb.begin(), bb.end()));
}

void assertKeyPublishToUsersTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<Trustchain::Actions::KeyPublishToUser> const& keyPublishes,
    std::vector<Tanker::Crypto::EncryptionKeyPair> const& userKeyPairs)
{
  REQUIRE(keyPublishes.size() == userKeyPairs.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].recipientPublicEncryptionKey() ==
          userKeyPairs[i].publicKey);
    CHECK(keyPublishes[i].resourceId() ==
          std::get<Trustchain::ResourceId>(resourceKey));
    CHECK_EQ(Crypto::sealDecrypt(keyPublishes[i].sealedSymmetricKey(),
                                 userKeyPairs[i]),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

void assertKeyPublishToUsersTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<KeyPublishToProvisionalUser> const& keyPublishes,
    std::vector<ProvisionalUsers::SecretUser> const& provisionalUsers)
{
  REQUIRE(keyPublishes.size() == provisionalUsers.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].appPublicSignatureKey() ==
          provisionalUsers[i].appSignatureKeyPair.publicKey);
    CHECK(keyPublishes[i].tankerPublicSignatureKey() ==
          provisionalUsers[i].tankerSignatureKeyPair.publicKey);
    CHECK(keyPublishes[i].resourceId() ==
          std::get<Trustchain::ResourceId>(resourceKey));
    CHECK_EQ(
        Crypto::sealDecrypt(
            Crypto::sealDecrypt(keyPublishes[i].twoTimesSealedSymmetricKey(),
                                provisionalUsers[i].tankerEncryptionKeyPair),
            provisionalUsers[i].appEncryptionKeyPair),
        std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

void assertKeyPublishToGroupTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<Trustchain::Actions::KeyPublishToUserGroup> const& keyPublishes,
    std::vector<Tanker::Crypto::EncryptionKeyPair> const& userKeyPairs)
{
  REQUIRE(keyPublishes.size() == userKeyPairs.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].recipientPublicEncryptionKey() ==
          userKeyPairs[i].publicKey);
    CHECK(keyPublishes[i].resourceId() ==
          std::get<Trustchain::ResourceId>(resourceKey));
    CHECK_EQ(Crypto::sealDecrypt(keyPublishes[i].sealedSymmetricKey(),
                                 userKeyPairs[i]),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}
}

using UsersPullResult = Tanker::Users::UserAccessor::PullResult;

TEST_CASE("generateRecipientList of a new user should return their user key")
{
  TrustchainBuilder builder;
  builder.makeUser3("newUser");
  builder.makeUser3("keySender");

  auto const newUser = *builder.findUser("newUser");
  auto const keySender = *builder.findUser("keySender");

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  REQUIRE_CALL(userAccessor,
               pull(trompeloeil::eq<gsl::span<Trustchain::UserId const>>(
                   gsl::span<Trustchain::UserId const>{newUser.userId})))
      .LR_RETURN(
          Tanker::makeCoTask(UsersPullResult{{newUser.asTankerUser()}, {}}));

  REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
      .LR_RETURN(
          Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

  REQUIRE_CALL(groupAccessor,
               getPublicEncryptionKeys(trompeloeil::eq(std::vector<GroupId>{})))
      .LR_RETURN(
          makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

  auto const recipients = AWAIT(Share::generateRecipientList(
      userAccessor,
      groupAccessor,
      {SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
          builder.trustchainId(), newUser.userId})}},
      {}));

  // there should be only user keys
  CHECK(recipients.recipientProvisionalUserKeys.size() == 0);
  CHECK(recipients.recipientGroupKeys.size() == 0);
  assertEqual<Crypto::PublicEncryptionKey>(
      recipients.recipientUserKeys,
      {newUser.userKeys.back().keyPair.publicKey});
}

TEST_CASE("generateRecipientList of a new group should return their group key")
{
  TrustchainBuilder builder;
  auto const newUser = builder.makeUser3("newUser");
  auto const keySender = builder.makeUser3("keySender");

  auto const newGroup =
      builder.makeGroup(keySender.user.devices.at(0), {newUser.user});

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  REQUIRE_CALL(userAccessor,
               pull(trompeloeil::eq<gsl::span<Trustchain::UserId const>>(
                   gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

  REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
      .LR_RETURN(
          Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

  REQUIRE_CALL(groupAccessor,
               getPublicEncryptionKeys(trompeloeil::eq(
                   std::vector<GroupId>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{
          {newGroup.group.tankerGroup.encryptionKeyPair.publicKey}, {}}));

  auto const recipients = AWAIT(
      Share::generateRecipientList(userAccessor,
                                   groupAccessor,
                                   {},
                                   {cppcodec::base64_rfc4648::encode<SGroupId>(
                                       newGroup.group.tankerGroup.id)}));

  // there should be only group keys
  CHECK(recipients.recipientUserKeys.size() == 0);
  CHECK(recipients.recipientProvisionalUserKeys.size() == 0);
  assertEqual<Crypto::PublicEncryptionKey>(
      recipients.recipientGroupKeys,
      {newGroup.group.tankerGroup.encryptionKeyPair.publicKey});
}

TEST_CASE(
    "generateRecipientList of a provisional user should return their group key")
{
  TrustchainBuilder builder;
  auto const provisionalUser = builder.makeProvisionalUser("bob@gmail");
  auto const keySender = builder.makeUser3("keySender");

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  REQUIRE_CALL(userAccessor,
               pull(trompeloeil::eq<gsl::span<Trustchain::UserId const>>(
                   gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

  REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
      .LR_RETURN(Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{
          provisionalUser.publicProvisionalUser}));

  REQUIRE_CALL(groupAccessor,
               getPublicEncryptionKeys(trompeloeil::eq(std::vector<GroupId>{})))
      .LR_RETURN(
          makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

  auto const recipients = AWAIT(Share::generateRecipientList(
      userAccessor, groupAccessor, {provisionalUser.spublicIdentity}, {}));

  CHECK(recipients.recipientUserKeys.size() == 0);
  CHECK(recipients.recipientGroupKeys.size() == 0);
  CHECK(recipients.recipientProvisionalUserKeys.size() == 1);
  CHECK(recipients.recipientProvisionalUserKeys[0].appSignaturePublicKey ==
        provisionalUser.secretProvisionalUser.appSignatureKeyPair.publicKey);
  CHECK(recipients.recipientProvisionalUserKeys[0].appEncryptionPublicKey ==
        provisionalUser.secretProvisionalUser.appEncryptionKeyPair.publicKey);
  CHECK(recipients.recipientProvisionalUserKeys[0].tankerSignaturePublicKey ==
        provisionalUser.secretProvisionalUser.tankerSignatureKeyPair.publicKey);
  CHECK(
      recipients.recipientProvisionalUserKeys[0].tankerEncryptionPublicKey ==
      provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair.publicKey);
}

TEST_CASE("generateRecipientList of a not-found user should throw")
{
  TrustchainBuilder builder;
  builder.makeUser3("newUser");
  builder.makeUser3("keySender");

  auto const newUser = *builder.findUser("newUser");
  auto const keySender = *builder.findUser("keySender");

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  REQUIRE_CALL(userAccessor,
               pull(trompeloeil::eq<gsl::span<Trustchain::UserId const>>(
                   gsl::span<Trustchain::UserId const>{newUser.userId})))
      .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {newUser.userId}}));

  REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
      .LR_RETURN(
          Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

  REQUIRE_CALL(groupAccessor,
               getPublicEncryptionKeys(trompeloeil::eq(std::vector<GroupId>{})))
      .LR_RETURN(
          makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

  TANKER_CHECK_THROWS_WITH_CODE(
      AWAIT(Share::generateRecipientList(
          userAccessor,
          groupAccessor,
          {SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
              builder.trustchainId(), newUser.userId})}},
          {})),
      make_error_code(Errc::InvalidArgument));
}

TEST_CASE("generateRecipientList of a not-found group should throw")
{
  TrustchainBuilder builder;
  auto const newUser = builder.makeUser3("newUser");
  auto const keySender = builder.makeUser3("keySender");

  auto const newGroup =
      builder.makeGroup(keySender.user.devices.at(0), {newUser.user});

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  REQUIRE_CALL(userAccessor,
               pull(trompeloeil::eq<gsl::span<Trustchain::UserId const>>(
                   gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

  REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
      .LR_RETURN(
          Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

  REQUIRE_CALL(groupAccessor,
               getPublicEncryptionKeys(trompeloeil::eq(
                   std::vector<GroupId>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{
          {}, {newGroup.group.tankerGroup.id}}));

  TANKER_CHECK_THROWS_WITH_CODE(AWAIT(Share::generateRecipientList(
                                    userAccessor,
                                    groupAccessor,
                                    {},
                                    {cppcodec::base64_rfc4648::encode<SGroupId>(
                                        newGroup.group.tankerGroup.id)})),
                                make_error_code(Errc::InvalidArgument));
}

template <typename T>
std::vector<T> extract(std::vector<std::vector<uint8_t>> const& blocks)
{
  std::vector<T> keyPublishes;
  for (auto const& block : blocks)
  {
    auto const entry = Serialization::deserialize<ServerEntry>(block);
    auto const keyPublish = entry.action().get_if<KeyPublish>();
    REQUIRE(keyPublish);
    auto const keyPublishTo = keyPublish->get_if<T>();
    keyPublishes.push_back(*keyPublishTo);
  }
  return keyPublishes;
}

TEST_CASE(
    "generateShareBlocks of a new user should generate one KeyPublishToUser "
    "block")
{
  TrustchainBuilder builder;
  builder.makeUser3("newUser");
  builder.makeUser3("keySender");

  auto const newUser = *builder.findUser("newUser");
  auto const keySender = *builder.findUser("keySender");
  auto const keySenderDevice = keySender.devices.front();

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource resourceId")}};

  auto const newUserKeyPair = newUser.userKeys.back();

  Share::KeyRecipients keyRecipients{
      {newUserKeyPair.keyPair.publicKey}, {}, {}};
  auto const blocks = Share::generateShareBlocks(
      builder.trustchainId(),
      keySenderDevice.id,
      keySenderDevice.keys.signatureKeyPair.privateKey,
      resourceKeys,
      keyRecipients);

  auto const keyPublishes =
      extract<Trustchain::Actions::KeyPublishToUser>(blocks);
  assertKeyPublishToUsersTargetedAt(
      resourceKeys[0], keyPublishes, {newUserKeyPair.keyPair});
}

TEST_CASE(
    "generateShareBlocks of a new user should generate one "
    "KeyPublishToProvisionalUser block")
{
  TrustchainBuilder builder;
  auto const provisionalUser = builder.makeProvisionalUser("bob@gmail");
  builder.makeUser3("keySender");

  auto const keySender = *builder.findUser("keySender");
  auto const keySenderDevice = keySender.devices.front();

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource mac")}};

  Share::KeyRecipients keyRecipients{
      {}, {provisionalUser.publicProvisionalUser}, {}};
  auto const blocks = Share::generateShareBlocks(
      builder.trustchainId(),
      keySenderDevice.id,
      keySenderDevice.keys.signatureKeyPair.privateKey,
      resourceKeys,
      keyRecipients);

  auto const keyPublishes = extract<KeyPublishToProvisionalUser>(blocks);
  assertKeyPublishToUsersTargetedAt(
      resourceKeys[0], keyPublishes, {provisionalUser.secretProvisionalUser});
}

TEST_CASE(
    "generateShareBlocks of a group should generate one KeyPublishToGroup "
    "block")
{
  TrustchainBuilder builder;
  auto const newUser = builder.makeUser3("newUser");
  auto const keySender = builder.makeUser3("keySender");
  auto const newGroup =
      builder.makeGroup(keySender.user.devices.at(0), {newUser.user});

  auto const keySenderDevice = keySender.user.devices.front();

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource resourceId")}};

  Share::KeyRecipients keyRecipients{
      {}, {}, {newGroup.group.asExternalGroup().publicEncryptionKey}};
  auto const blocks = Share::generateShareBlocks(
      builder.trustchainId(),
      keySenderDevice.id,
      keySenderDevice.keys.signatureKeyPair.privateKey,
      resourceKeys,
      keyRecipients);

  auto const keyPublishes =
      extract<Trustchain::Actions::KeyPublishToUserGroup>(blocks);
  assertKeyPublishToGroupTargetedAt(
      resourceKeys[0],
      keyPublishes,
      {newGroup.group.tankerGroup.encryptionKeyPair});
}
