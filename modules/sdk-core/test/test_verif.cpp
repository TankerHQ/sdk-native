#include <Tanker/Groups/Verif/UserGroupAddition.hpp>
#include <Tanker/Groups/Verif/UserGroupCreation.hpp>
#include <Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Const.hpp>
#include <Helpers/Errors.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>

#include <catch2/catch_test_macros.hpp>

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
  SECTION("it should reject an incorrectly signed delegation for a device")
  {
    unconstify(deviceEntry.delegationSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt),
        Errc::InvalidDelegationSignature);
  }

  SECTION("should reject an incorrectly signed device")
  {
    unconstify(deviceEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt),
        Errc::InvalidSignature);
  }

  SECTION("should accept a valid DeviceCreation")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(
            deviceEntry, context, Tanker::Users::User{}),
        Errc::UserAlreadyExists);
  }

  SECTION("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(
        Verif::verifyDeviceCreation(deviceEntry, context, std::nullopt));
  }
}

void deviceCreationCommonChecks(Users::User const& tankerUser,
                                Trustchain::Context const& context,
                                DeviceCreation const& secondDeviceEntry)
{
  SECTION("it should reject an incorrectly signed delegation for a device")
  {
    unconstify(secondDeviceEntry.delegationSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidDelegationSignature);
  }

  SECTION("should reject an incorrectly signed device")
  {
    unconstify(secondDeviceEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidSignature);
  }

  SECTION("should reject an incorrect userId")
  {
    unconstify(secondDeviceEntry.author())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser),
        Errc::InvalidUserId);
  }

  SECTION("should reject a DeviceCreation with a missing author")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, std::nullopt),
        Errc::InvalidAuthor);
  }

  SECTION("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(
        Verif::verifyDeviceCreation(secondDeviceEntry, context, tankerUser));
  }
}

void testUserGroupCreationCommon(Users::Device const& authorDevice,
                                 UserGroupCreation const& gcEntry)
{
  SECTION("should reject a UserGroupCreation if the group already exists")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, ExternalGroup{}),
        Errc::InvalidGroup);
  }

  SECTION("should reject an incorrectly signed UserGroupCreation")
  {
    unconstify(gcEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, std::nullopt),
        Errc::InvalidSignature);
  }

  SECTION("should reject a UserGroupCreation with invalid selfSignature")
  {
    unconstify(gcEntry.selfSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice, std::nullopt),
        Errc::InvalidSignature);
  }

  SECTION("should accept a valid UserGroupCreation")
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

  SECTION("should reject a UserGroupAddition for an unknown group")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, std::nullopt),
        Errc::InvalidGroup);
  }

  SECTION("should reject an incorrectly signed UserGroupAddition")
  {
    unconstify(gaEntry.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup),
        Errc::InvalidSignature);
  }

  SECTION("should reject a UserGroupAddition with invalid selfSignature")
  {
    unconstify(gaEntry.selfSignature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, baseGroup),
        Errc::InvalidSignature);
  }

  SECTION("should accept a valid UserGroupAddition")
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

  SECTION("Entry level")
  {
    SECTION("Valid TrustchainCreation block")
    {
      CHECK_NOTHROW(Verif::verifyTrustchainCreation(rootEntry, trustchainId));
    }
  }

  SECTION("Contextual level")
  {
    SECTION("TrustchainId mismatch")
    {
      Trustchain::TrustchainId trustchainId(rootEntry.hash());
      trustchainId[0]++;

      TANKER_CHECK_THROWS_WITH_CODE(
          Verif::verifyTrustchainCreation(rootEntry, trustchainId),
          Errc::InvalidHash);
    }

    SECTION("Valid TrustchainCreation block")
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

  SECTION("should reject an incorrect userKey")
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

  SECTION("should reject a device creation 3 if the user has no user key")
  {
    auto tankerUser = Users::User{user};
    unconstify(tankerUser.userKey()) = std::nullopt;

    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(
            deviceEntry, generator.context(), tankerUser),
        Errc::InvalidUserKey);
  }

  SECTION("should reject an incorrect userKey")
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

  SECTION("should reject a device creation v1 if the user has a userKey")
  {
    auto const keyPair = Crypto::makeEncryptionKeyPair();
    alice.addUserKey(keyPair);
    TANKER_CHECK_THROWS_WITH_CODE(
        Verif::verifyDeviceCreation(deviceEntry, generator.context(), alice),
        Errc::InvalidUserKey);
  }
}

TEST_CASE("Verif UserGroupCreation")
{
  Test::Generator generator;

  auto const alice = generator.makeUser("alice");
  auto& firstDevice = alice.devices().front();

  SECTION("V1")
  {
    auto const aliceGroup = generator.makeGroupV1(firstDevice, {alice});
    testUserGroupCreationCommon(
        firstDevice,
        boost::variant2::get<UserGroupCreation>(aliceGroup.entries().front()));
  }
  SECTION("V2")
  {
    auto const aliceGroup = generator.makeGroupV2(firstDevice, {alice});
    testUserGroupCreationCommon(
        firstDevice,
        boost::variant2::get<UserGroupCreation>(aliceGroup.entries().front()));
  }
  SECTION("V3")
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
  SECTION("V1")
  {
    auto aliceGroup = generator.makeGroupV1(aliceDevice, {alice});
    auto const previousGroup = aliceGroup;

    testUserGroupAdditionCommon(
        aliceDevice, aliceGroup.addUsersV1(aliceDevice, {bob}), previousGroup);
  }
  SECTION("V2")
  {
    auto aliceGroup = generator.makeGroupV2(aliceDevice, {alice});
    auto const previousGroup = aliceGroup;

    testUserGroupAdditionCommon(
        aliceDevice, aliceGroup.addUsersV2(aliceDevice, {bob}), previousGroup);
  }
  SECTION("V3")
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

  SECTION("should reject an incorrectly signed ProvisionalIdentityClaim")
  {
    unconstify(provisionalIdentityClaim.signature())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SECTION("should reject a ProvisionalIdentityClaim with invalid app signature")
  {
    unconstify(provisionalIdentityClaim.authorSignatureByAppKey())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SECTION(
      "should reject a ProvisionalIdentityClaim with invalid tanker "
      "signature")
  {
    unconstify(provisionalIdentityClaim.authorSignatureByTankerKey())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidSignature);
  }

  SECTION("should reject a ProvisionalIdentityClaim with an incorrect user ID")
  {
    unconstify(authorDevice.userId())[0]++;
    TANKER_CHECK_THROWS_WITH_CODE(Verif::verifyProvisionalIdentityClaim(
                                      provisionalIdentityClaim, authorDevice),
                                  Errc::InvalidUserId);
  }

  SECTION("should accept a valid ProvisionalIdentityClaim")
  {
    CHECK_NOTHROW(Verif::verifyProvisionalIdentityClaim(
        provisionalIdentityClaim, authorDevice));
  }
}
