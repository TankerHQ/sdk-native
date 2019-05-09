#include <Tanker/Share.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/UserAccessor.hpp>

#include <Helpers/Await.hpp>

#include "MockConnection.hpp"
#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

#include <mockaron/mockaron.hpp>

#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using Tanker::Trustchain::GroupId;
using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace
{
template <typename T>
bool hasDevice(gsl::span<Device const> devices,
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
    CHECK_EQ(Crypto::sealDecrypt<Crypto::SymmetricKey>(
                 keyPublishes[i].sealedSymmetricKey(), userKeyPairs[i]),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

void assertKeyPublishToUsersTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<KeyPublishToProvisionalUser> const& keyPublishes,
    std::vector<SecretProvisionalUser> const& provisionalUsers)
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
        Crypto::sealDecrypt<Crypto::SymmetricKey>(
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
    CHECK_EQ(Crypto::sealDecrypt<Crypto::SymmetricKey>(
                 keyPublishes[i].sealedSymmetricKey(), userKeyPairs[i]),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

class GroupAccessorMock : public mockaron::mock_impl
{
public:
  GroupAccessorMock()
  {
    MOCKARON_DECLARE_IMPL_CUSTOM(
        tc::cotask<GroupAccessor::PullResult>(gsl::span<GroupId const>),
        GroupAccessor::PullResult,
        GroupAccessor,
        pull);
  }

  MAKE_MOCK1(pull, GroupAccessor::PullResult(gsl::span<GroupId const>));
};
}

TEST_CASE("generateRecipientList of a new user should return their user key")
{
  TrustchainBuilder builder;
  builder.makeUser3("newUser");
  builder.makeUser3("keySender");

  auto const newUser = *builder.getUser("newUser");
  auto const keySender = *builder.getUser("keySender");

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  auto mockConnection = std::make_unique<MockConnection>();
  ALLOW_CALL(*mockConnection, on("new relevant block", trompeloeil::_));
  Client client(std::move(mockConnection));

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<Trustchain::UserId const>{newUser.userId})))
      .LR_RETURN((UserAccessor::PullResult{{newUser.asTankerUser()}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  auto const recipients = AWAIT(Share::generateRecipientList(
      userAccessor.get(),
      groupAccessor.get(),
      client,
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

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  auto mockConnection = std::make_unique<MockConnection>();
  ALLOW_CALL(*mockConnection, on("new relevant block", trompeloeil::_));
  Client client(std::move(mockConnection));

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN((UserAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<GroupId const>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(
          (GroupAccessor::PullResult{{newGroup.group.asExternalGroup()}, {}}));

  auto const recipients = AWAIT(
      Share::generateRecipientList(userAccessor.get(),
                                   groupAccessor.get(),
                                   client,
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
  Identity::PublicProvisionalIdentity publicProvisionalIdentity{
      builder.trustchainId(),
      provisionalUser.target,
      provisionalUser.value,
      provisionalUser.appSignatureKeyPair.publicKey,
      provisionalUser.appEncryptionKeyPair.publicKey,
  };
  auto const keySender = builder.makeUser3("keySender");

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  auto upmockConnection = std::make_unique<MockConnection>();
  auto const mockConnection = upmockConnection.get();
  ALLOW_CALL(*mockConnection, on("new relevant block", trompeloeil::_));
  Client client(std::move(upmockConnection));

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN((UserAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(*mockConnection,
               emit("get public provisional identities", trompeloeil::_))
      .LR_RETURN(WRAP_COTASK(
          nlohmann::json(
              {{{"SignaturePublicKey",
                 provisionalUser.tankerSignatureKeyPair.publicKey},
                {"EncryptionPublicKey",
                 provisionalUser.tankerEncryptionKeyPair.publicKey}}})
              .dump()));

  auto const recipients = AWAIT(Share::generateRecipientList(
      userAccessor.get(),
      groupAccessor.get(),
      client,
      {SPublicIdentity{to_string(publicProvisionalIdentity)}},
      {}));

  CHECK(recipients.recipientUserKeys.size() == 0);
  CHECK(recipients.recipientGroupKeys.size() == 0);
  CHECK(recipients.recipientProvisionalUserKeys.size() == 1);
  CHECK(recipients.recipientProvisionalUserKeys[0].appSignaturePublicKey ==
        provisionalUser.appSignatureKeyPair.publicKey);
  CHECK(recipients.recipientProvisionalUserKeys[0].appEncryptionPublicKey ==
        provisionalUser.appEncryptionKeyPair.publicKey);
  CHECK(recipients.recipientProvisionalUserKeys[0].tankerSignaturePublicKey ==
        provisionalUser.tankerSignatureKeyPair.publicKey);
  CHECK(recipients.recipientProvisionalUserKeys[0].tankerEncryptionPublicKey ==
        provisionalUser.tankerEncryptionKeyPair.publicKey);
}

TEST_CASE("generateRecipientList of a not-found user should throw")
{
  TrustchainBuilder builder;
  builder.makeUser3("newUser");
  builder.makeUser3("keySender");

  auto const newUser = *builder.getUser("newUser");
  auto const keySender = *builder.getUser("keySender");

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  auto mockConnection = std::make_unique<MockConnection>();
  ALLOW_CALL(*mockConnection, on("new relevant block", trompeloeil::_));
  Client client(std::move(mockConnection));

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<Trustchain::UserId const>{newUser.userId})))
      .LR_RETURN((UserAccessor::PullResult{{}, {newUser.userId}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  CHECK_THROWS_AS(
      AWAIT(Share::generateRecipientList(
          userAccessor.get(),
          groupAccessor.get(),
          client,
          {SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
              builder.trustchainId(), newUser.userId})}},
          {})),
      Error::RecipientNotFound);
}

TEST_CASE("generateRecipientList of a not-found group should throw")
{
  TrustchainBuilder builder;
  auto const newUser = builder.makeUser3("newUser");
  auto const keySender = builder.makeUser3("keySender");

  auto const newGroup =
      builder.makeGroup(keySender.user.devices.at(0), {newUser.user});

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  auto mockConnection = std::make_unique<MockConnection>();
  ALLOW_CALL(*mockConnection, on("new relevant block", trompeloeil::_));
  Client client(std::move(mockConnection));

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<Trustchain::UserId const>{})))
      .LR_RETURN((UserAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<GroupId const>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(
          (GroupAccessor::PullResult{{}, {newGroup.group.tankerGroup.id}}));

  CHECK_THROWS_AS(AWAIT(Share::generateRecipientList(
                      userAccessor.get(),
                      groupAccessor.get(),
                      client,
                      {},
                      {cppcodec::base64_rfc4648::encode<SGroupId>(
                          newGroup.group.tankerGroup.id)})),
                  Error::RecipientNotFound);
}

template <typename T>
std::vector<T> extract(std::vector<std::vector<uint8_t>> const& blocks)
{
  std::vector<T> keyPublishes;
  for (auto const& block : blocks)
  {
    auto const entry =
        blockToServerEntry(Serialization::deserialize<Block>(block));
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

  auto const newUser = *builder.getUser("newUser");
  auto const keySender = *builder.getUser("keySender");
  auto const keySenderDevice = keySender.devices.front();
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource resourceId")}};

  auto const newUserKeyPair = newUser.userKeys.back();

  Share::KeyRecipients keyRecipients{
      {newUserKeyPair.keyPair.publicKey}, {}, {}};
  auto const blocks = Share::generateShareBlocks(
      keySenderBlockGenerator, resourceKeys, keyRecipients);

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

  auto const keySender = *builder.getUser("keySender");
  auto const keySenderDevice = keySender.devices.front();
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource mac")}};

  Share::KeyRecipients keyRecipients{
      {},
      {{
          provisionalUser.appSignatureKeyPair.publicKey,
          provisionalUser.appEncryptionKeyPair.publicKey,
          provisionalUser.tankerSignatureKeyPair.publicKey,
          provisionalUser.tankerEncryptionKeyPair.publicKey,
      }},
      {}};
  auto const blocks = Share::generateShareBlocks(
      keySenderBlockGenerator, resourceKeys, keyRecipients);

  auto const keyPublishes = extract<KeyPublishToProvisionalUser>(blocks);
  assertKeyPublishToUsersTargetedAt(
      resourceKeys[0], keyPublishes, {provisionalUser});
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
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {
      {make<Crypto::SymmetricKey>("symmkey"),
       make<Trustchain::ResourceId>("resource resourceId")}};

  Share::KeyRecipients keyRecipients{
      {}, {}, {newGroup.group.asExternalGroup().publicEncryptionKey}};
  auto const blocks = Share::generateShareBlocks(
      keySenderBlockGenerator, resourceKeys, keyRecipients);

  auto const keyPublishes =
      extract<Trustchain::Actions::KeyPublishToUserGroup>(blocks);
  assertKeyPublishToGroupTargetedAt(
      resourceKeys[0],
      keyPublishes,
      {newGroup.group.tankerGroup.encryptionKeyPair});
}
