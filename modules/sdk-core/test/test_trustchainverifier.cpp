#include <Tanker/TrustchainVerifier.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest.h>
#include <mpark/variant.hpp>

#include <cstring>
#include <memory>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;

TEST_CASE("TrustchainVerifier")
{
  TrustchainBuilder builder;
  auto const rootEntry = blockToUnverifiedEntry(builder.blocks().front());

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(rootEntry)));

  auto const resourceId = make<Trustchain::ResourceId>("resourceId");
  auto const symmetricKey = make<Crypto::SymmetricKey>("symmetric key");

  auto const groupStore = std::make_unique<GroupStore>(db.get());

  SUBCASE("verifies a valid trustchain creation")
  {
    auto const contactStore = builder.makeContactStoreWith({}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(rootEntry)));
  }

  SUBCASE("verifies a valid device creation")
  {
    auto const userResult = builder.makeUser3("bob");

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(userResult.entry)));
  }

  SUBCASE("verifies a valid keyPublishToDevice")
  {
    auto const userResult = builder.makeUser1("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice1("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const blocksKp2d = builder.shareToDevice(
        deviceResult.device, userResult.user, resourceId, symmetricKey);

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(
        AWAIT_VOID(verifier.verify(blockToUnverifiedEntry(blocksKp2d[0]))));
  }

  SUBCASE("verifies a valid keyPublishToUser")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const aliceUserResult = builder.makeUser3("alice");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(aliceUserResult.entry)));
    auto const blockKp2u = builder.shareToUser(
        deviceResult.device, aliceUserResult.user, resourceId, symmetricKey);

    auto const contactStore =
        builder.makeContactStoreWith({"bob", "alice"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(
        AWAIT_VOID(verifier.verify(blockToUnverifiedEntry(blockKp2u))));
  }

  SUBCASE("verifies a valid keyPublishToUserGroup")
  {
    auto const thomasUserResult = builder.makeUser3("thomas");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(thomasUserResult.entry)));
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const resultGroup = builder.makeGroup(
        deviceResult.device, {userResult.user, thomasUserResult.user});
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(resultGroup.entry)));
    auto const blockKp2g = builder.shareToUserGroup(
        deviceResult.device, resultGroup.group, resourceId, symmetricKey);

    auto const contactStore =
        builder.makeContactStoreWith({"bob", "thomas"}, db.get());
    auto const updatedGroupStore =
        builder.makeGroupStore(userResult.user, db.get());
    TrustchainVerifier const verifier(builder.trustchainId(),
                                      db.get(),
                                      contactStore.get(),
                                      updatedGroupStore.get());

    CHECK_NOTHROW(
        AWAIT_VOID(verifier.verify(blockToUnverifiedEntry(blockKp2g))));
  }

  SUBCASE("verifies a valid deviceRevocation")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const targetResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));

    auto bobUser = builder.getUser("bob");

    auto const revokeBlock = builder.revokeDevice2(
        deviceResult.device, targetResult.device, *bobUser);
    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());

    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(
        AWAIT_VOID(verifier.verify(blockToUnverifiedEntry(revokeBlock))));
  }

  SUBCASE("verifies a valid userGroupAddition")
  {
    auto const thomasUserResult = builder.makeUser3("thomas");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(thomasUserResult.entry)));
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const resultGroup =
        builder.makeGroup(deviceResult.device, {userResult.user});
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(resultGroup.entry)));

    auto const updatedGroupStore =
        builder.makeGroupStore(userResult.user, db.get());

    auto const resultUserGroupAddition = builder.addUserToGroup(
        deviceResult.device, resultGroup.group, {thomasUserResult.user});

    auto const contactStore =
        builder.makeContactStoreWith({"bob", "thomas"}, db.get());
    TrustchainVerifier const verifier(builder.trustchainId(),
                                      db.get(),
                                      contactStore.get(),
                                      updatedGroupStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(resultUserGroupAddition.entry)));
  }

  SUBCASE("verifies a valid userGroupCreation")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const resultGroup =
        builder.makeGroup(deviceResult.device, {userResult.user});

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(resultGroup.entry)));
  }

  SUBCASE("verifies a valid ProvisionalIdentityClaim")
  {
    auto const userResult = builder.makeUser3("alice");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));

    auto const provisionalUser = builder.makeProvisionalUser("alice@email.com");
    auto picEntry = builder.claimProvisionalIdentity("alice", provisionalUser);

    auto const contactStore = builder.makeContactStoreWith({"alice"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(picEntry)));
  }

  SUBCASE("reject a userGroupCreation when group already exists")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const resultGroup =
        builder.makeGroup(deviceResult.device, {userResult.user});
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(resultGroup.entry)));

    auto const updatedGroupStore =
        builder.makeGroupStore(userResult.user, db.get());

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(builder.trustchainId(),
                                      db.get(),
                                      contactStore.get(),
                                      updatedGroupStore.get());

    CHECK_THROWS_AS(AWAIT_VOID(verifier.verify(resultGroup.entry)),
                    Error::VerificationFailed);
  }

  SUBCASE("throws if the author does not exist")
  {
    builder.makeUser3("bob");
    auto const deviceResult = builder.makeDevice3("bob");

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_THROWS_AS(AWAIT_VOID(verifier.verify(deviceResult.entry)),
                    Error::VerificationFailed);
  }

  SUBCASE("second device creation throws if user does not exist")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");

    // Do not add user 'bob' to contactStore:
    auto const contactStore = builder.makeContactStoreWith({}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_THROWS_AS(AWAIT_VOID(verifier.verify(deviceResult.entry)),
                    Error::VerificationFailed);
  }

  SUBCASE("verif kp2g throws if group does not exists")
  {
    auto const thomasUserResult = builder.makeUser3("thomas");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(thomasUserResult.entry)));
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const resultGroup = builder.makeGroup(
        deviceResult.device, {userResult.user, thomasUserResult.user});
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(resultGroup.entry)));
    auto const blockKp2g = builder.shareToUserGroup(
        deviceResult.device, resultGroup.group, resourceId, symmetricKey);

    auto const contactStore =
        builder.makeContactStoreWith({"bob", "thomas"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get(), groupStore.get());

    CHECK_THROWS_AS(
        AWAIT_VOID(verifier.verify(blockToUnverifiedEntry(blockKp2g))),
        Error::VerificationFailed);
  }
}
