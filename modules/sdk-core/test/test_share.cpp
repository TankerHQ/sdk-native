#include <Tanker/Share.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
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
#include "TestVerifier.hpp"
#include "TrustchainGenerator.hpp"
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
    ResourceKeys::KeysResult::value_type const& resourceKey,
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
    ResourceKeys::KeysResult::value_type const& resourceKey,
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
    ResourceKeys::KeysResult::value_type const& resourceKey,
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

TEST_CASE("generateRecipientList")
{
  Test::Generator generator;
  auto const newUser = generator.makeUser("newUser");
  auto const keySender = generator.makeUser("keySender");

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  SUBCASE("a new user should return their user key")
  {

    REQUIRE_CALL(userAccessor,
                 pull(gsl::span<Trustchain::UserId const>{newUser.id()}))
        .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{newUser}, {}}));

    REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
        .LR_RETURN(
            Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

    REQUIRE_CALL(groupAccessor, getPublicEncryptionKeys(std::vector<GroupId>{}))
        .LR_RETURN(makeCoTask(
            Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

    auto const recipients = AWAIT(Share::generateRecipientList(
        userAccessor,
        groupAccessor,
        {SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
            generator.context().id(), newUser.id()})}},
        {}));

    // there should be only user keys
    CHECK(recipients.recipientProvisionalUserKeys.size() == 0);
    CHECK(recipients.recipientGroupKeys.size() == 0);
    assertEqual<Crypto::PublicEncryptionKey>(
        recipients.recipientUserKeys, {newUser.userKeys().back().publicKey});
  }

  SUBCASE("a new group should return their group key")
  {

    auto const newGroup = keySender.makeGroup({newUser});

    REQUIRE_CALL(userAccessor, pull(gsl::span<Trustchain::UserId const>{}))
        .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

    REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
        .LR_RETURN(
            Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

    REQUIRE_CALL(groupAccessor,
                 getPublicEncryptionKeys(std::vector<GroupId>{newGroup.id()}))
        .LR_RETURN(makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{
            {newGroup.currentEncKp().publicKey}, {}}));

    auto const recipients = AWAIT(Share::generateRecipientList(
        userAccessor,
        groupAccessor,
        {},
        {cppcodec::base64_rfc4648::encode<SGroupId>(newGroup.id())}));

    // there should be only group keys
    CHECK(recipients.recipientUserKeys.size() == 0);
    CHECK(recipients.recipientProvisionalUserKeys.size() == 0);
    assertEqual<Crypto::PublicEncryptionKey>(
        recipients.recipientGroupKeys, {newGroup.currentEncKp().publicKey});
  }

  SUBCASE("a provisional user should return their provisional keys")
  {
    auto const provisionalUser = generator.makeProvisionalUser("bob@gmail");

    REQUIRE_CALL(userAccessor, pull(gsl::span<Trustchain::UserId const>{}))
        .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

    REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
        .LR_RETURN(Tanker::makeCoTask(
            std::vector<ProvisionalUsers::PublicUser>{provisionalUser}));

    REQUIRE_CALL(groupAccessor, getPublicEncryptionKeys(std::vector<GroupId>{}))
        .LR_RETURN(makeCoTask(
            Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

    auto const recipients = AWAIT(Share::generateRecipientList(
        userAccessor,
        groupAccessor,
        {SPublicIdentity{
            to_string(Identity::getPublicIdentity(provisionalUser))}},
        {}));

    CHECK(recipients.recipientUserKeys.size() == 0);
    CHECK(recipients.recipientGroupKeys.size() == 0);
    CHECK(recipients.recipientProvisionalUserKeys.size() == 1);
    CHECK(recipients.recipientProvisionalUserKeys[0].appSignaturePublicKey ==
          provisionalUser.appSignatureKeyPair().publicKey);
    CHECK(recipients.recipientProvisionalUserKeys[0].appEncryptionPublicKey ==
          provisionalUser.appEncryptionKeyPair().publicKey);
    CHECK(recipients.recipientProvisionalUserKeys[0].tankerSignaturePublicKey ==
          provisionalUser.tankerSignatureKeyPair().publicKey);
    CHECK(
        recipients.recipientProvisionalUserKeys[0].tankerEncryptionPublicKey ==
        provisionalUser.tankerEncryptionKeyPair().publicKey);
  }

  SUBCASE("a not-found user should throw")
  {
    REQUIRE_CALL(userAccessor,
                 pull(gsl::span<Trustchain::UserId const>{newUser.id()}))
        .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {newUser.id()}}));

    REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
        .LR_RETURN(
            Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

    REQUIRE_CALL(groupAccessor, getPublicEncryptionKeys(std::vector<GroupId>{}))
        .LR_RETURN(makeCoTask(
            Groups::Accessor::PublicEncryptionKeyPullResult{{}, {}}));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Share::generateRecipientList(
            userAccessor,
            groupAccessor,
            {SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
                generator.context().id(), newUser.id()})}},
            {})),
        make_error_code(Errc::InvalidArgument));
  }

  SUBCASE("a not-found group should throw")
  {
    auto const newGroup = keySender.makeGroup({newUser});

    REQUIRE_CALL(userAccessor, pull(gsl::span<Trustchain::UserId const>{}))
        .LR_RETURN(Tanker::makeCoTask(UsersPullResult{{}, {}}));

    REQUIRE_CALL(userAccessor, pullProvisional(trompeloeil::_))
        .LR_RETURN(
            Tanker::makeCoTask(std::vector<ProvisionalUsers::PublicUser>{}));

    REQUIRE_CALL(groupAccessor,
                 getPublicEncryptionKeys(std::vector<GroupId>{newGroup.id()}))
        .LR_RETURN(makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{
            {}, {newGroup.id()}}));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Share::generateRecipientList(
            userAccessor,
            groupAccessor,
            {},
            {cppcodec::base64_rfc4648::encode<SGroupId>(newGroup.id())})),
        make_error_code(Errc::InvalidArgument));
  }
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

TEST_CASE("generateShareBlocks")
{
  Test::Generator generator;
  auto const& newUser = generator.makeUser("newUser");
  auto const& keySender = generator.makeUser("keySender");
  auto const& keySenderDevice = keySender.devices().front();

  SUBCASE("for a user should generate one KeyPublishToUser block")
  {
    ResourceKeys::KeysResult resourceKeys = {
        {make<Crypto::SymmetricKey>("symmkey"),
         make<Trustchain::ResourceId>("resource resourceId")}};

    auto const newUserKeyPair = newUser.userKeys().back();

    Share::KeyRecipients keyRecipients{{newUserKeyPair.publicKey}, {}, {}};
    auto const blocks = Share::generateShareBlocks(
        generator.context().id(),
        keySenderDevice.id(),
        keySenderDevice.keys().signatureKeyPair.privateKey,
        resourceKeys,
        keyRecipients);

    auto const keyPublishes =
        extract<Trustchain::Actions::KeyPublishToUser>(blocks);
    assertKeyPublishToUsersTargetedAt(
        resourceKeys[0], keyPublishes, {newUserKeyPair});
  }

  SUBCASE("for a user should generate one KeyPublishToProvisionalUser block")
  {
    auto const provisionalUser = generator.makeProvisionalUser("bob@gmail");

    ResourceKeys::KeysResult resourceKeys = {
        {make<Crypto::SymmetricKey>("symmkey"),
         make<Trustchain::ResourceId>("resource mac")}};

    Share::KeyRecipients keyRecipients{{}, {provisionalUser}, {}};
    auto const blocks = Share::generateShareBlocks(
        generator.context().id(),
        keySenderDevice.id(),
        keySenderDevice.keys().signatureKeyPair.privateKey,
        resourceKeys,
        keyRecipients);

    auto const keyPublishes = extract<KeyPublishToProvisionalUser>(blocks);
    assertKeyPublishToUsersTargetedAt(
        resourceKeys[0], keyPublishes, {provisionalUser});
  }

  SUBCASE("for a group should generate one KeyPublishToGroup block")
  {
    auto const newGroup = keySender.makeGroup({newUser});

    ResourceKeys::KeysResult resourceKeys = {
        {make<Crypto::SymmetricKey>("symmkey"),
         make<Trustchain::ResourceId>("resource resourceId")}};

    Share::KeyRecipients keyRecipients{
        {}, {}, {newGroup.currentEncKp().publicKey}};
    auto const blocks = Share::generateShareBlocks(
        generator.context().id(),
        keySenderDevice.id(),
        keySenderDevice.keys().signatureKeyPair.privateKey,
        resourceKeys,
        keyRecipients);

    auto const keyPublishes =
        extract<Trustchain::Actions::KeyPublishToUserGroup>(blocks);
    assertKeyPublishToGroupTargetedAt(
        resourceKeys[0], keyPublishes, {newGroup.currentEncKp()});
  }
}
