#include <Tanker/Share.hpp>

#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/UserAccessor.hpp>

#include <Helpers/Await.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"
#include "UserAccessorMock.hpp"

#include <doctest.h>

#include <mockaron/mockaron.hpp>

#include <trompeloeil.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

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

void assertDevicesEqual(
    std::vector<TrustchainBuilder::Device> const& builderDevices,
    std::vector<Device> const& tankerDevices)
{
  std::vector<DeviceId> builderDeviceIds;
  for (auto const& device : builderDevices)
    builderDeviceIds.push_back(device.keys.deviceId);

  std::vector<DeviceId> tankerDeviceIds;
  for (auto const& entry : tankerDevices)
    tankerDeviceIds.push_back(entry.id);

  assertEqual(builderDeviceIds, tankerDeviceIds);
}

void assertKeyPublishToDevicesTargetedAt(
    Share::ResourceKey const& resourceKey,
    TrustchainBuilder::Device const& keySenderDevice,
    std::vector<KeyPublishToDevice> const& keyPublishes,
    std::vector<TrustchainBuilder::Device> const& devices)
{
  REQUIRE(keyPublishes.size() == devices.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].recipient == devices[i].keys.deviceId);
    CHECK(keyPublishes[i].mac == std::get<Crypto::Mac>(resourceKey));
    CHECK_EQ(Crypto::asymDecrypt<Crypto::SymmetricKey>(
                 keyPublishes[i].key,
                 keySenderDevice.keys.encryptionKeyPair.publicKey,
                 devices[i].keys.encryptionKeyPair.privateKey),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

void assertKeyPublishToDevicesTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<KeyPublishToUser> const& keyPublishes,
    std::vector<Tanker::Crypto::EncryptionKeyPair> const& userKeyPairs)
{
  REQUIRE(keyPublishes.size() == userKeyPairs.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].recipientPublicEncryptionKey ==
          userKeyPairs[i].publicKey);
    CHECK(keyPublishes[i].mac == std::get<Crypto::Mac>(resourceKey));
    CHECK_EQ(Crypto::sealDecrypt<Crypto::SymmetricKey>(keyPublishes[i].key,
                                                       userKeyPairs[i]),
             std::get<Crypto::SymmetricKey>(resourceKey));
  }
}

void assertKeyPublishToGroupTargetedAt(
    Share::ResourceKey const& resourceKey,
    std::vector<KeyPublishToUserGroup> const& keyPublishes,
    std::vector<Tanker::Crypto::EncryptionKeyPair> const& userKeyPairs)
{
  REQUIRE(keyPublishes.size() == userKeyPairs.size());

  for (unsigned int i = 0; i < keyPublishes.size(); ++i)
  {
    CHECK(keyPublishes[i].recipientPublicEncryptionKey ==
          userKeyPairs[i].publicKey);
    CHECK(keyPublishes[i].resourceId == std::get<Crypto::Mac>(resourceKey));
    CHECK_EQ(Crypto::sealDecrypt<Crypto::SymmetricKey>(keyPublishes[i].key,
                                                       userKeyPairs[i]),
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

TEST_CASE(
    "generateRecipientList of and old user should return their device entries")
{
  TrustchainBuilder builder;
  builder.makeUser1("oldUser");
  builder.makeDevice1("oldUser");
  builder.makeUser3("keySender");

  auto const oldUser = *builder.getUser("oldUser");
  auto const keySender = *builder.getUser("keySender");

  mockaron::mock<UserAccessor, UserAccessorMock> userAccessor;
  mockaron::mock<GroupAccessor, GroupAccessorMock> groupAccessor;

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<UserId const>{oldUser.userId})))
      .LR_RETURN((UserAccessor::PullResult{{oldUser.asTankerUser()}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  auto const recipients =
      AWAIT(Share::generateRecipientList(userAccessor.get(),
                                         groupAccessor.get(),
                                         std::vector<UserId>{oldUser.userId},
                                         {}));

  // there should be only device entries
  CHECK(recipients.recipientUserKeys.empty());
  CHECK(recipients.recipientGroupKeys.empty());
  assertDevicesEqual(oldUser.devices, recipients.recipientDevices);
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

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<UserId const>{newUser.userId})))
      .LR_RETURN((UserAccessor::PullResult{{newUser.asTankerUser()}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  auto const recipients = AWAIT(Share::generateRecipientList(
      userAccessor.get(), groupAccessor.get(), {newUser.userId}, {}));

  // there should be only user keys
  CHECK(recipients.recipientDevices.size() == 0);
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

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<UserId const>{})))
      .LR_RETURN((UserAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<GroupId const>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(
          (GroupAccessor::PullResult{{newGroup.group.asExternalGroup()}, {}}));

  auto const recipients =
      AWAIT(Share::generateRecipientList(userAccessor.get(),
                                         groupAccessor.get(),
                                         {},
                                         {newGroup.group.tankerGroup.id}));

  // there should be only group keys
  CHECK(recipients.recipientDevices.size() == 0);
  CHECK(recipients.recipientUserKeys.size() == 0);
  assertEqual<Crypto::PublicEncryptionKey>(
      recipients.recipientGroupKeys,
      {newGroup.group.tankerGroup.encryptionKeyPair.publicKey});
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

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<UserId const>{newUser.userId})))
      .LR_RETURN((UserAccessor::PullResult{{}, {newUser.userId}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<GroupId const>{})))
      .LR_RETURN((GroupAccessor::PullResult{{}, {}}));

  CHECK_THROWS_AS(
      AWAIT(Share::generateRecipientList(
          userAccessor.get(), groupAccessor.get(), {newUser.userId}, {})),
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

  REQUIRE_CALL(userAccessor.get_mock_impl(),
               pull(trompeloeil::eq(gsl::span<UserId const>{})))
      .LR_RETURN((UserAccessor::PullResult{{}, {}}));

  REQUIRE_CALL(groupAccessor.get_mock_impl(),
               pull(trompeloeil::eq(
                   gsl::span<GroupId const>{newGroup.group.tankerGroup.id})))
      .LR_RETURN(
          (GroupAccessor::PullResult{{}, {newGroup.group.tankerGroup.id}}));

  CHECK_THROWS_AS(
      AWAIT(Share::generateRecipientList(userAccessor.get(),
                                         groupAccessor.get(),
                                         {},
                                         {newGroup.group.tankerGroup.id})),
      Error::RecipientNotFound);
}

template <typename T>
std::vector<T> extract(std::vector<std::vector<uint8_t>> const& blocks)
{
  std::vector<T> keyPublishes;
  for (auto const& block : blocks)
  {
    auto const entry =
        blockToUnverifiedEntry(Serialization::deserialize<Block>(block));
    auto const keyPublish = mpark::get_if<T>(&entry.action.variant());
    REQUIRE(keyPublish);
    keyPublishes.push_back(*keyPublish);
  }
  return keyPublishes;
}

TEST_CASE(
    "generateShareBlocks of and old user should generate KeyPublishToDevice1 "
    "blocks "
    "for each target device")
{
  TrustchainBuilder builder;
  builder.makeUser1("oldUser");
  builder.makeDevice1("oldUser");
  builder.makeUser3("keySender");

  auto const oldUser = *builder.getUser("oldUser");
  auto const keySender = *builder.getUser("keySender");
  auto const keySenderDevice = keySender.devices.front();
  auto const keySenderPrivateEncryptionKey =
      keySenderDevice.keys.encryptionKeyPair.privateKey;
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {{make<Crypto::SymmetricKey>("symmkey"),
                                       make<Crypto::Mac>("resource mac")}};

  Share::KeyRecipients keyRecipients{
      {},
      {},
      {oldUser.asTankerUser().devices[0], oldUser.asTankerUser().devices[1]}};

  auto const blocks = Share::generateShareBlocks(keySenderPrivateEncryptionKey,
                                                 keySenderBlockGenerator,
                                                 resourceKeys,
                                                 keyRecipients);

  auto const keyPublishes = extract<KeyPublishToDevice>(blocks);
  assertKeyPublishToDevicesTargetedAt(
      resourceKeys[0], keySenderDevice, keyPublishes, oldUser.devices);
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
  auto const keySenderPrivateEncryptionKey =
      keySenderDevice.keys.encryptionKeyPair.privateKey;
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {{make<Crypto::SymmetricKey>("symmkey"),
                                       make<Crypto::Mac>("resource mac")}};

  auto const newUserKeyPair = newUser.userKeys.back();

  Share::KeyRecipients keyRecipients{
      {newUserKeyPair.keyPair.publicKey}, {}, {}};
  auto const blocks = Share::generateShareBlocks(keySenderPrivateEncryptionKey,
                                                 keySenderBlockGenerator,
                                                 resourceKeys,
                                                 keyRecipients);

  auto const keyPublishes = extract<KeyPublishToUser>(blocks);
  assertKeyPublishToDevicesTargetedAt(
      resourceKeys[0], keyPublishes, {newUserKeyPair.keyPair});
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
  auto const keySenderPrivateEncryptionKey =
      keySenderDevice.keys.encryptionKeyPair.privateKey;
  auto const keySenderBlockGenerator =
      builder.makeBlockGenerator(keySenderDevice);

  Share::ResourceKeys resourceKeys = {{make<Crypto::SymmetricKey>("symmkey"),
                                       make<Crypto::Mac>("resource mac")}};

  Share::KeyRecipients keyRecipients{
      {}, {newGroup.group.asExternalGroup().publicEncryptionKey}, {}};
  auto const blocks = Share::generateShareBlocks(keySenderPrivateEncryptionKey,
                                                 keySenderBlockGenerator,
                                                 resourceKeys,
                                                 keyRecipients);

  auto const keyPublishes = extract<KeyPublishToUserGroup>(blocks);
  assertKeyPublishToGroupTargetedAt(
      resourceKeys[0],
      keyPublishes,
      {newGroup.group.tankerGroup.encryptionKeyPair});
}
