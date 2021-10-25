#include <Tanker/Share.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "GroupAccessorMock.hpp"
#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <doctest/doctest.h>

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
    CHECK(keyPublishes[i].resourceId() == resourceKey.resourceId);
    CHECK_EQ(Crypto::sealDecrypt(keyPublishes[i].sealedSymmetricKey(),
                                 userKeyPairs[i]),
             resourceKey.key);
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
    CHECK(keyPublishes[i].resourceId() == resourceKey.resourceId);
    CHECK_EQ(
        Crypto::sealDecrypt(
            Crypto::sealDecrypt(keyPublishes[i].twoTimesSealedSymmetricKey(),
                                provisionalUsers[i].tankerEncryptionKeyPair),
            provisionalUsers[i].appEncryptionKeyPair),
        resourceKey.key);
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
    CHECK(keyPublishes[i].resourceId() == resourceKey.resourceId);
    CHECK_EQ(Crypto::sealDecrypt(keyPublishes[i].sealedSymmetricKey(),
                                 userKeyPairs[i]),
             resourceKey.key);
  }
}
}

using UserPullResult = Tanker::Users::UserAccessor::UserPullResult;

TEST_CASE("generateRecipientList")
{
  Test::Generator generator;
  auto const newUser = generator.makeUser("newUser");
  auto const keySender = generator.makeUser("keySender");

  UserAccessorMock userAccessor;
  GroupAccessorMock groupAccessor;

  SUBCASE("a new user should return their user key")
  {

    REQUIRE_CALL(
        userAccessor,
        pull(std::vector{newUser.id()}, Users::IRequester::IsLight::Yes))
        .LR_RETURN(Tanker::makeCoTask(UserPullResult{{newUser}, {}}));

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

    REQUIRE_CALL(userAccessor,
                 pull(std::vector<Trustchain::UserId>{},
                      Users::IRequester::IsLight::Yes))
        .LR_RETURN(Tanker::makeCoTask(UserPullResult{{}, {}}));

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
        {mgs::base64::encode<SGroupId>(newGroup.id())}));

    // there should be only group keys
    CHECK(recipients.recipientUserKeys.size() == 0);
    CHECK(recipients.recipientProvisionalUserKeys.size() == 0);
    assertEqual<Crypto::PublicEncryptionKey>(
        recipients.recipientGroupKeys, {newGroup.currentEncKp().publicKey});
  }

  SUBCASE("a provisional user should return their provisional keys")
  {
    auto const provisionalUser = generator.makeProvisionalUser("bob@gmail");

    REQUIRE_CALL(userAccessor,
                 pull(std::vector<Trustchain::UserId>{},
                      Users::IRequester::IsLight::Yes))
        .LR_RETURN(Tanker::makeCoTask(UserPullResult{{}, {}}));

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
    CHECK(recipients.recipientProvisionalUserKeys[0].appSignaturePublicKey() ==
          provisionalUser.appSignatureKeyPair().publicKey);
    CHECK(recipients.recipientProvisionalUserKeys[0].appEncryptionPublicKey() ==
          provisionalUser.appEncryptionKeyPair().publicKey);
    CHECK(
        recipients.recipientProvisionalUserKeys[0].tankerSignaturePublicKey() ==
        provisionalUser.tankerSignatureKeyPair().publicKey);
    CHECK(recipients.recipientProvisionalUserKeys[0]
              .tankerEncryptionPublicKey() ==
          provisionalUser.tankerEncryptionKeyPair().publicKey);
  }

  SUBCASE("a not-found user should throw")
  {
    REQUIRE_CALL(
        userAccessor,
        pull(std::vector{newUser.id()}, Users::IRequester::IsLight::Yes))
        .LR_RETURN(Tanker::makeCoTask(UserPullResult{{}, {newUser.id()}}));

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

    REQUIRE_CALL(userAccessor,
                 pull(std::vector<Trustchain::UserId>{},
                      Users::IRequester::IsLight::Yes))
        .LR_RETURN(Tanker::makeCoTask(UserPullResult{{}, {}}));

    REQUIRE_CALL(groupAccessor,
                 getPublicEncryptionKeys(std::vector<GroupId>{newGroup.id()}))
        .LR_RETURN(makeCoTask(Groups::Accessor::PublicEncryptionKeyPullResult{
            {}, {newGroup.id()}}));

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Share::generateRecipientList(
            userAccessor,
            groupAccessor,
            {},
            {mgs::base64::encode<SGroupId>(newGroup.id())})),
        make_error_code(Errc::InvalidArgument));
  }
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

    assertKeyPublishToUsersTargetedAt(
        resourceKeys[0], blocks.keyPublishesToUsers, {newUserKeyPair});
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

    assertKeyPublishToUsersTargetedAt(resourceKeys[0],
                                      blocks.keyPublishesToProvisionalUsers,
                                      {provisionalUser});
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

    assertKeyPublishToGroupTargetedAt(resourceKeys[0],
                                      blocks.keyPublishesToUserGroups,
                                      {newGroup.currentEncKp()});
  }
}
