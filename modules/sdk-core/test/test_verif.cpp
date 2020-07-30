#include <Tanker/Groups/Verif/UserGroupAddition.hpp>
#include <Tanker/Groups/Verif/UserGroupCreation.hpp>
#include <Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Const.hpp>
#include <Helpers/Errors.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <doctest/doctest.h>

#include "TrustchainGenerator.hpp"

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker;
using namespace Tanker::Verif;

namespace
{
template <typename T, typename U>
auto& extract(U& action)
{
  return action.template get<T>();
}

void deviceCreationCommonChecks(DeviceCreation const& deviceEntry,
                                Trustchain::Context const& context)
{
  SUBCASE("it should reject an incorrectly signed delegation for a device")
  {
    unconstify(deviceEntry.delegationSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt),
        Errc::InvalidDelegationSignature);
  }

  SUBCASE("should reject an incorrectly signed device")
  {
    unconstify(deviceEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt),
        Errc::InvalidSignature);
  }

  SUBCASE("should accept a valid DeviceCreation")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(
            deviceEntry, context, Tanker::Users::User{}),
        Errc::UserAlreadyExists);
  }

  SUBCASE("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt));
  }
}

void deviceCreationCommonChecks(Users::User const& tankerUser,
                                Trustchain::Context const& context,
                                DeviceCreation const& secondDeviceEntry)
{
  SUBCASE("it should reject a device creation when author device is revoked")
  {
    auto& authorDevice = tankerUser.devices().front();
    unconstify(authorDevice).setRevoked();
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidAuthor);
  }

  SUBCASE("it should reject an incorrectly signed delegation for a device")
  {
    unconstify(secondDeviceEntry.delegationSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidDelegationSignature);
  }

  SUBCASE("should reject an incorrectly signed device")
  {
    unconstify(secondDeviceEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidSignature);
  }

  SUBCASE("should reject an incorrect userId")
  {
    unconstify(secondDeviceEntry.author())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidUserId);
  }

  SUBCASE("should reject a DeviceCreation with a missing author")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, std::nullopt),
        Errc::InvalidAuthor);
  }

  SUBCASE("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser));
  }
}

void deviceRevocationCommonChecks(DeviceRevocation const& deviceRevocation,
                                  Users::User& user)
{
  SUBCASE("should reject an incorrectly signed DeviceRevocation")
  {
    unconstify(deviceRevocation.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(deviceRevocation, user),
        Errc::InvalidSignature);
  }

  SUBCASE("should reject a revocation from a revoked device")
  {
    unconstify(user.devices()[0]).setRevoked();
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(deviceRevocation, user),
        Errc::AuthorIsRevoked);
  }

  SUBCASE("should reject a revocation when user is not found")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(deviceRevocation, std::nullopt),
        Errc::InvalidAuthor);
  }

  SUBCASE("should reject a revocation of an already revoked device")
  {
    unconstify(user.devices()[1]).setRevoked();
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(deviceRevocation, user),
        Errc::InvalidTargetDevice);
  }

  SUBCASE("should accept a valid deviceRevocation")
  {
    CHECK_NOTHROW(Verif::verifyDeviceRevocation(deviceRevocation, user));
  }
}

void testUserGroupCreationCommon(Users::Device const& authorDevice,
                                 UserGroupCreation const& gcEntry)
{
  SUBCASE("should reject a UserGroupCreation if the group already exists")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, ExternalGroup{}),
        Errc::InvalidGroup);
  }

  SUBCASE("should reject an incorrectly signed UserGroupCreation")
  {
    unconstify(gcEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, std::nullopt),
        Errc::InvalidSignature);
  }

  SUBCASE("should reject a UserGroupCreation with invalid selfSignature")
  {
    unconstify(gcEntry.selfSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, std::nullopt),
        Errc::InvalidSignature);
  }

  SUBCASE("should accept a valid UserGroupCreation")
  {
    CHECK_NOTHROW(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, std::nullopt));
  }
}

void testUserGroupAdditionCommon(Test::Device const& authorDevice,
                                 UserGroupAddition const& gaEntry,
                                 Test::Group const& group)
{
  auto const baseGroup = BaseGroup{group};

  SUBCASE("should reject a UserGroupAddition for an unknown group")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, std::nullopt),
        Errc::InvalidGroup);
  }

  SUBCASE("should reject an incorrectly signed UserGroupAddition")
  {
    unconstify(gaEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup),
        Errc::InvalidSignature);
  }

  SUBCASE(
      "should reject a UserGroupAddition where previousGroupBlock is not the "
      "hash of last modification")
  {
    unconstify(gaEntry.previousGroupBlockHash())[0]++;
    unconstify(gaEntry.selfSignature()) =
        Crypto::sign(gaEntry.signatureData(), group.currentSigKp().privateKey);
    unconstify(gaEntry.signature()) = Crypto::sign(
        getHash(gaEntry), authorDevice.keys().signatureKeyPair.privateKey);
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup),
        Errc::InvalidGroup);
  }

  SUBCASE("should reject a UserGroupAddition with invalid selfSignature")
  {
    unconstify(gaEntry.selfSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup),
        Errc::InvalidSignature);
  }

  SUBCASE("should accept a valid UserGroupAddition")
  {
    CHECK_NOTHROW(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup));
  }
}
}

TEST_CASE("Verif TrustchainCreation")
{
  Test::Generator generator;
  auto const rootEntry = generator.rootBlock();
  auto const& trustchainId = generator.context().id();

  SUBCASE("Entry level")
  {
    SUBCASE("Valid TrustchainCreation block")
    {
      CHECK_NOTHROW(Verif::verifyTrustchainCreation(rootEntry, trustchainId));
    }
  }

  SUBCASE("Contextual level")
  {
    SUBCASE("TrustchainId mismatch")
    {
      Trustchain::TrustchainId trustchainId(rootEntry.hash());
      trustchainId[0]++;

      TANKER_CHECK_THROWS_WITH_CODE(
          Verif::verifyTrustchainCreation(rootEntry, trustchainId),
          Errc::InvalidHash);
    }

    SUBCASE("Valid TrustchainCreation block")
    {
      Trustchain::TrustchainId trustchainId(rootEntry.hash());

      CHECK_NOTHROW(Verif::verifyTrustchainCreation(rootEntry, trustchainId));
    }
  }
}

TEST_CASE("Verif DeviceCreation v3 - Trustchain author")
{
  Test::Generator generator;
  auto const user = generator.makeUser("alice");

  deviceCreationCommonChecks(user.entries().front(), generator.context());
}

TEST_CASE("Verif DeviceCreation v1 - Trustchain author")
{
  Test::Generator generator;
  auto const user = generator.makeUserV1("alice");

  deviceCreationCommonChecks(user.entries().front(), generator.context());
}

TEST_CASE("Verif DeviceCreation v3 - DeviceCreation v3 author")
{
  Test::Generator generator;

  auto user = generator.makeUser("alice");
  auto& firstDevice = user.devices().front();
  auto& secondDevice = user.addDevice();
  auto deviceEntry = secondDevice.action;

  deviceCreationCommonChecks(user, generator.context(), deviceEntry);

  SUBCASE("should reject an incorrect userKey")
  {
    auto& dc3 = extract<DeviceCreation3>(deviceEntry);

    unconstify(dc3.publicUserEncryptionKey())[0]++;
    unconstify(dc3.delegationSignature()) =
        Crypto::sign(dc3.delegationSignatureData(),
                     firstDevice.keys().signatureKeyPair.privateKey);

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, generator.context(), user),
        Errc::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceCreation v3 - DeviceCreation v1 author")
{
  Test::Generator generator;

  auto user = generator.makeUserV1("alice");
  auto& firstDevice = user.devices().front();
  // otherwise we can't create a deviceV3
  user.addUserKey();
  auto& secondDevice = user.addDevice();
  auto const deviceEntry = secondDevice.action;

  SUBCASE("should reject a device creation 3 if the user has no user key")
  {
    auto tankerUser = Users::User{user};
    unconstify(tankerUser.userKey()) = std::nullopt;

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(
            deviceEntry, generator.context(), tankerUser),
        Errc::InvalidUserKey);
  }

  SUBCASE("should reject an incorrect userKey")
  {
    auto& dc3 = extract<DeviceCreation3>(deviceEntry);

    unconstify(dc3.publicUserEncryptionKey())[0]++;

    unconstify(dc3.delegationSignature()) =
        Crypto::sign(dc3.delegationSignatureData(),
                     firstDevice.keys().signatureKeyPair.privateKey);

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, generator.context(), user),
        Errc::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceCreation v1 - DeviceCreation v1 author")
{
  Test::Generator generator;

  auto alice = generator.makeUserV1("alice");
  auto secondDevice = alice.addDeviceV1();
  auto const deviceEntry = secondDevice.action;

  deviceCreationCommonChecks(alice, generator.context(), deviceEntry);

  SUBCASE("should reject a device creation v1 if the user has a userKey")
  {
    auto const keyPair = Crypto::makeEncryptionKeyPair();
    alice.addUserKey(keyPair);
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, generator.context(), alice),
        Errc::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceRevocationV1")
{
  Test::Generator generator;

  auto alice = generator.makeUserV1("alice");
  auto& secondDevice = alice.addDeviceV1();
  auto aliceUser = Users::User{alice};

  auto const revokeEntry = alice.revokeDeviceV1(secondDevice);

  SUBCASE("common")
  {
    deviceRevocationCommonChecks(revokeEntry, aliceUser);
  }

  SUBCASE("should reject a revocation for another user's device")
  {
    auto bob = generator.makeUserV1("bob");
    auto bobDevice = bob.makeDeviceV1();

    auto const action = alice.revokeDeviceV1(bobDevice);
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser), Errc::InvalidUser);
  }

  SUBCASE("should reject a revocation whose user has a userKey")
  {
    unconstify(aliceUser.userKey()) = Crypto::makeEncryptionKeyPair().publicKey;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(revokeEntry, aliceUser),
        Errc::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceRevocationV2")
{
  Test::Generator generator;

  auto alice = generator.makeUser("alice");
  auto& secondDevice = alice.addDevice();
  alice.addDevice();
  auto aliceUser = Users::User{alice};
  auto const action = alice.revokeDevice(secondDevice);

  SUBCASE("common")
  {
    deviceRevocationCommonChecks(action, aliceUser);
  }

  auto bob = generator.makeUserV1("bob");
  auto& bobDevice = bob.addDeviceV1();
  auto& bobOtherDevice = bob.addDeviceV1();
  auto const bobUser = Users::User{bob};
  auto entryUserV1 = bob.revokeDeviceForMigration(bobDevice, bobOtherDevice);

  SUBCASE(
      "should reject a revocation whose user has no userKey when "
      "PreviousPublicEncryptionKey is not a zero array")
  {
    unconstify(entryUserV1.previousPublicEncryptionKey())[0]++;

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(entryUserV1, bobUser),
        Errc::InvalidEncryptionKey);
  }

  SUBCASE(
      "should reject a revocation whose user has no userKey when the "
      "EncryptedKeyForPreviousUserKey is not a zero array")
  {
    unconstify(entryUserV1.sealedKeyForPreviousUserKey())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(entryUserV1, bobUser),
        Errc::InvalidUserKey);
  }

  SUBCASE("should reject a revocation for another user's device")
  {
    auto const revokeEntry = alice.revokeDevice(bobOtherDevice);
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(revokeEntry, bobUser), Errc::InvalidUser);
  }

  SUBCASE(
      "should reject a revocation whose user has a userKey when the "
      "previousEncryptedKey does not match the userKey")
  {
    unconstify(action.previousPublicEncryptionKey())[0]++;

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser),
        Errc::InvalidEncryptionKey);
  }

  SUBCASE(
      "should reject a DeviceRevocation2 whose userKeys field does not have "
      "exactly one element per device")
  {
    auto& sealedUserKeysForDevices =
        unconstify(action.sealedUserKeysForDevices());
    sealedUserKeysForDevices.erase(sealedUserKeysForDevices.begin());

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser),
        Errc::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceCreationV2 with a userKey fields that contains "
      "the target device of the revocation")
  {
    auto& sealedUserKeysForDevices =
        unconstify(action.sealedUserKeysForDevices());
    sealedUserKeysForDevices.erase(sealedUserKeysForDevices.begin());
    auto const sealedPrivateEncryptionKey =
        make<Crypto::SealedPrivateEncryptionKey>("encrypted private key");
    sealedUserKeysForDevices.emplace_back(secondDevice.id(),
                                          sealedPrivateEncryptionKey);

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser),
        Errc::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceRevocation whose userKeys fields has a device "
      "that does not belong to the author's devices")
  {
    auto& sealedUserKeysForDevices =
        unconstify(action.sealedUserKeysForDevices());
    sealedUserKeysForDevices.erase(sealedUserKeysForDevices.begin());

    auto const sealedPrivateEncryptionKey =
        make<Crypto::SealedPrivateEncryptionKey>("encrypted private key");
    sealedUserKeysForDevices.emplace_back(bobDevice.id(),
                                          sealedPrivateEncryptionKey);

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser),
        Errc::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceRevocation whose userKeys fields has a duplicates")
  {
    auto& sealedUserKeysForDevices =
        unconstify(action.sealedUserKeysForDevices());
    sealedUserKeysForDevices.erase(sealedUserKeysForDevices.begin());
    sealedUserKeysForDevices.push_back(*sealedUserKeysForDevices.begin());

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceRevocation(action, aliceUser),
        Errc::InvalidUserKeys);
  }
}

TEST_CASE("Verif UserGroupCreation")
{
  Test::Generator generator;

  auto const alice = generator.makeUser("alice");
  auto& firstDevice = alice.devices().front();

  SUBCASE("V1")
  {
    auto const aliceGroup = generator.makeGroupV1(firstDevice, {alice});
    testUserGroupCreationCommon(
        firstDevice,
        boost::variant2::get<UserGroupCreation>(aliceGroup.entries().front()));
  }
  SUBCASE("V2")
  {
    auto const aliceGroup = generator.makeGroup(firstDevice, {alice});
    testUserGroupCreationCommon(
        firstDevice,
        boost::variant2::get<UserGroupCreation>(aliceGroup.entries().front()));
  }
}

TEST_CASE("Verif UserGroupAddition")
{
  Test::Generator generator;

  auto alice = generator.makeUser("alice");
  auto const& aliceDevice = alice.addDevice();
  auto const bob = generator.makeUser("bob");
  SUBCASE("V1")
  {
    auto aliceGroup = generator.makeGroupV1(aliceDevice, {alice});
    auto const previousGroup = aliceGroup;

    testUserGroupAdditionCommon(
        aliceDevice, aliceGroup.addUsersV1(aliceDevice, {bob}), previousGroup);
  }
  SUBCASE("V2")
  {
    auto aliceGroup = generator.makeGroup(aliceDevice, {alice});
    auto const previousGroup = aliceGroup;

    testUserGroupAdditionCommon(
        aliceDevice, aliceGroup.addUsers(aliceDevice, {bob}), previousGroup);
  }
}

TEST_CASE("Verif ProvisionalIdentityClaim")
{
  Test::Generator generator;

  auto const alice = generator.makeUser("alice");
  auto const provisionalUser =
      generator.makeProvisionalUser("alice.test@tanker.io");
  auto const provisionalIdentityClaim = alice.claim(provisionalUser);

  auto& authorDevice = alice.devices().front();

  SUBCASE("should reject an incorrectly signed ProvisionalIdentityClaim")
  {
    unconstify(provisionalIdentityClaim.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SUBCASE("should reject a ProvisionalIdentityClaim with invalid app signature")
  {
    unconstify(provisionalIdentityClaim.authorSignatureByAppKey())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SUBCASE(
      "should reject a ProvisionalIdentityClaim with invalid tanker "
      "signature")
  {
    unconstify(provisionalIdentityClaim.authorSignatureByTankerKey())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SUBCASE("should reject a ProvisionalIdentityClaim with an incorrect user ID")
  {
    unconstify(authorDevice.userId())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidUserId);
  }

  SUBCASE("should accept a valid ProvisionalIdentityClaim")
  {
    CHECK_NOTHROW(Verif::verifyProvisionalIdentityClaim(
        provisionalIdentityClaim, authorDevice));
  }
}
