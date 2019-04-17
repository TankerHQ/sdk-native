#include <Tanker/Actions/KeyPublishToProvisionalUser.hpp>
#include <Tanker/Actions/KeyPublishToUserGroup.hpp>
#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>
#include <Tanker/Verif/KeyPublishToDevice.hpp>
#include <Tanker/Verif/KeyPublishToUser.hpp>
#include <Tanker/Verif/KeyPublishToUserGroup.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>
#include <Tanker/Verif/UserGroupAddition.hpp>
#include <Tanker/Verif/UserGroupCreation.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>
#include <mpark/variant.hpp>

#include <cstring>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using Tanker::Trustchain::Actions::DeviceCreation;
using namespace Tanker;

#define CHECK_VERIFICATION_FAILED_WITH(functionCall, errCode) \
  do                                                          \
  {                                                           \
    try                                                       \
    {                                                         \
      functionCall;                                           \
    }                                                         \
    catch (Error::VerificationFailed const& err)              \
    {                                                         \
      CHECK_EQ(err.code(), errCode);                          \
      break;                                                  \
    }                                                         \
    catch (...)                                               \
    {                                                         \
    }                                                         \
    REQUIRE(false);                                           \
  } while (0)

namespace
{
template <typename T>
T extractDeviceCreation(Action const& action)
{
  return mpark::get<Trustchain::Actions::DeviceCreation>(action.variant())
      .get<T>();
}

DeviceRevocation2 extractDeviceRevocation2(Action const& action)
{
  return mpark::get<DeviceRevocation2>(
      mpark::get<DeviceRevocation>(action.variant()).variant());
}

Crypto::Signature forgeDelegationSignature(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    Trustchain::UserId const& userId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  std::vector<std::uint8_t> toSign;
  toSign.insert(toSign.end(),
                ephemeralPublicSignatureKey.begin(),
                ephemeralPublicSignatureKey.end());
  toSign.insert(toSign.end(), userId.begin(), userId.end());
  return Crypto::sign(toSign, privateSignatureKey);
}

DeviceCreation::v1 forgeDeviceCreation(DeviceCreation::v1 const& old,
                                       Trustchain::UserId const& newId,
                                       Crypto::Signature const& signature)
{

  return DeviceCreation::v1(old.ephemeralPublicSignatureKey(),
                            newId,
                            signature,
                            old.publicSignatureKey(),
                            old.publicEncryptionKey());
}

DeviceCreation::v3 forgeDeviceCreation(DeviceCreation::v3 const& old,
                                       Trustchain::UserId const& newId,
                                       Crypto::Signature const& signature)
{
  return DeviceCreation::v3(
      old.ephemeralPublicSignatureKey(),
      newId,
      signature,
      old.publicSignatureKey(),
      old.publicEncryptionKey(),
      old.publicUserEncryptionKey(),
      old.sealedPrivateUserEncryptionKey(),
      (old.isGhostDevice() ? DeviceCreation::DeviceType::GhostDevice :
                             DeviceCreation::DeviceType::Device));
}

template <typename T>
void deviceCreationCommonChecks(TrustchainBuilder::ResultUser user,
                                TrustchainCreation const& trustchainCreation)
{
  SUBCASE("it should reject an incorrectly signed delegation for a device")
  {
    auto const deviceCreation = extractDeviceCreation<T>(user.entry.action);
    auto delegationSignature = deviceCreation.delegationSignature();
    delegationSignature[0]++;
    auto const forgedDeviceCreation = forgeDeviceCreation(
        deviceCreation, deviceCreation.userId(), delegationSignature);
    user.entry.action =
        Trustchain::Actions::DeviceCreation{forgedDeviceCreation};
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(user.entry, trustchainCreation),
        Error::VerificationCode::InvalidDelegationSignature);
  }

  SUBCASE("should reject an incorrectly signed device")
  {
    user.entry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(user.entry, trustchainCreation),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(Verif::verifyDeviceCreation(user.entry, trustchainCreation));
  }
}

template <typename T>
void deviceCreationCommonChecks(TrustchainBuilder::ResultUser user,
                                Device authorDevice,
                                TrustchainBuilder::ResultDevice secondDevice)
{
  auto const tankerUser = user.user.asTankerUser();

  SUBCASE("it should reject a device creation when author device is revoked")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("it should reject an incorrectly signed delegation for a device")
  {
    auto const deviceCreation =
        extractDeviceCreation<T>(secondDevice.entry.action);
    auto delegationSignature = deviceCreation.delegationSignature();
    delegationSignature[0]++;
    auto const forgedDeviceCreation = forgeDeviceCreation(
        deviceCreation, deviceCreation.userId(), delegationSignature);
    secondDevice.entry.action =
        Trustchain::Actions::DeviceCreation{forgedDeviceCreation};
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidDelegationSignature);
  }

  SUBCASE("should reject an incorrectly signed device")
  {
    secondDevice.entry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject an incorrect userId")
  {
    auto const authorPrivateSignatureKey =
        user.user.devices.front().keys.signatureKeyPair.privateKey;
    auto const deviceCreation =
        extractDeviceCreation<T>(secondDevice.entry.action);
    auto userId = deviceCreation.userId();
    userId[0]++;
    auto const delegationSignature = forgeDelegationSignature(
        secondDevice.device.delegation.ephemeralKeyPair.publicKey,
        userId,
        authorPrivateSignatureKey);
    auto const forgedDeviceCreation =
        forgeDeviceCreation(deviceCreation, userId, delegationSignature);

    secondDevice.entry.action =
        Trustchain::Actions::DeviceCreation{forgedDeviceCreation};
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidUserId);
  }

  SUBCASE("should accept a valid DeviceCreation")
  {
    CHECK_NOTHROW(Verif::verifyDeviceCreation(
        secondDevice.entry, authorDevice, tankerUser));
  }
}

void deviceRevocationCommonChecks(UnverifiedEntry deviceRevocation,
                                  Device authorDevice,
                                  Device targetDevice,
                                  User const& user)
{
  SUBCASE("should reject an incorrectly signed DeviceRevocation")
  {
    deviceRevocation.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            deviceRevocation, authorDevice, targetDevice, user),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a revocation from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            deviceRevocation, authorDevice, targetDevice, user),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should reject a revocation of an already revoked device")
  {
    targetDevice.revokedAtBlkIndex = targetDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            deviceRevocation, authorDevice, targetDevice, user),
        Error::VerificationCode::InvalidTargetDevice);
  }

  SUBCASE("should accept a valid deviceRevocation")
  {
    CHECK_NOTHROW(Verif::verifyDeviceRevocation(
        deviceRevocation, authorDevice, targetDevice, user));
  }
}
}

TEST_CASE("Verif TrustchainCreation")
{
  TrustchainBuilder builder;
  auto rootEntry = blockToUnverifiedEntry(builder.blocks().front());

  SUBCASE("Entry level")
  {
    SUBCASE("Invalid author")
    {
      rootEntry.author[0]++;

      CHECK_VERIFICATION_FAILED_WITH(
          Verif::verifyTrustchainCreation(rootEntry, builder.trustchainId()),
          Error::VerificationCode::InvalidAuthor);
    }

    SUBCASE("Invalid signature")
    {
      rootEntry.signature[0]++;

      CHECK_VERIFICATION_FAILED_WITH(
          Verif::verifyTrustchainCreation(rootEntry, builder.trustchainId()),
          Error::VerificationCode::InvalidSignature);
    }

    SUBCASE("Valid TrustchainCreation block")
    {
      CHECK_NOTHROW(
          Verif::verifyTrustchainCreation(rootEntry, builder.trustchainId()));
    }
  }

  SUBCASE("Contextual level")
  {
    SUBCASE("TrustchainId mismatch")
    {
      Trustchain::TrustchainId trustchainId(rootEntry.hash);
      trustchainId[0]++;

      CHECK_VERIFICATION_FAILED_WITH(
          Verif::verifyTrustchainCreation(rootEntry, trustchainId),
          Error::VerificationCode::InvalidHash);
    }

    SUBCASE("Valid TrustchainCreation block")
    {
      Trustchain::TrustchainId trustchainId(rootEntry.hash);

      CHECK_NOTHROW(Verif::verifyTrustchainCreation(rootEntry, trustchainId));
    }
  }
}

TEST_CASE("Verif DeviceCreation v3 - Trustchain author")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser3("alice");

  auto const authorEntry =
      toVerifiedEntry(blockToUnverifiedEntry(builder.blocks()[0]));
  auto const trustchainCreation =
      mpark::get<TrustchainCreation>(authorEntry.action.variant());

  deviceCreationCommonChecks<Trustchain::Actions::DeviceCreation::v3>(
      user, trustchainCreation);
}

TEST_CASE("Verif DeviceCreation v1 - Trustchain author")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser1("alice");

  auto const authorEntry =
      toVerifiedEntry(blockToUnverifiedEntry(builder.blocks()[0]));
  auto const trustchainCreation =
      mpark::get<TrustchainCreation>(authorEntry.action.variant());

  deviceCreationCommonChecks<Trustchain::Actions::DeviceCreation::v1>(user, trustchainCreation);
}

TEST_CASE("Verif DeviceCreation v3 - DeviceCreation v3 author")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser3("alice");
  auto secondDevice = builder.makeDevice3("alice");

  auto const authorDevice = user.user.devices.front().asTankerDevice();

  deviceCreationCommonChecks<Trustchain::Actions::DeviceCreation::v3>(
      user, authorDevice, secondDevice);

  SUBCASE("should reject an incorrect userKey")
  {
    using Trustchain::Actions::DeviceCreation;
    auto const dc3 =
        extractDeviceCreation<DeviceCreation::v3>(secondDevice.entry.action);

    auto publicUserEncryptionKey = dc3.publicUserEncryptionKey();
    publicUserEncryptionKey[0]++;

    DeviceCreation::v3 const forgedDeviceCreation(
        secondDevice.device.delegation.ephemeralKeyPair.publicKey,
        secondDevice.device.delegation.userId,
        secondDevice.device.delegation.signature,
        dc3.publicSignatureKey(),
        dc3.publicEncryptionKey(),
        publicUserEncryptionKey,
        dc3.sealedPrivateUserEncryptionKey(),
        DeviceCreation::DeviceType::Device);

    secondDevice.entry.action = DeviceCreation{forgedDeviceCreation};
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, user.user.asTankerUser()),
        Error::VerificationCode::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceCreation v3 - DeviceCreation v1 author")
{
  TrustchainBuilder builder;

  auto const user = builder.makeUser1("alice");
  auto secondDevice = builder.makeDevice3("alice");
  auto const authorDevice = user.user.devices.front().asTankerDevice();
  auto tankerUser = user.user.asTankerUser();

  SUBCASE("should reject a device creation 3 if the user has no user key")
  {
    tankerUser.userKey = nonstd::nullopt;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidUserKey);
  }

  SUBCASE("should reject an incorrect userKey")
  {
    using Trustchain::Actions::DeviceCreation;
    auto const dc3 =
        extractDeviceCreation<DeviceCreation::v3>(secondDevice.entry.action);

    auto publicUserEncryptionKey = dc3.publicUserEncryptionKey();
    publicUserEncryptionKey[0]++;

    DeviceCreation::v3 const forgedDeviceCreation(
        secondDevice.device.delegation.ephemeralKeyPair.publicKey,
        secondDevice.device.delegation.userId,
        secondDevice.device.delegation.signature,
        dc3.publicSignatureKey(),
        dc3.publicEncryptionKey(),
        publicUserEncryptionKey,
        dc3.sealedPrivateUserEncryptionKey(),
        DeviceCreation::DeviceType::Device);
    secondDevice.entry.action = DeviceCreation{forgedDeviceCreation};

    tankerUser.userKey = secondDevice.user.userKey;

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceCreation v1 - DeviceCreation v1 author")
{
  TrustchainBuilder builder;

  auto alice = builder.makeUser1("alice");
  auto secondDevice = builder.makeDevice1("alice");
  auto const authorDevice = alice.user.devices.front().asTankerDevice();

  deviceCreationCommonChecks<Trustchain::Actions::DeviceCreation::v1>(
      alice, authorDevice, secondDevice);

  SUBCASE("should reject a device creation v1 if the user has a userKey")
  {
    auto const keyPair = Crypto::makeEncryptionKeyPair();
    auto tankerUser = alice.user.asTankerUser();
    tankerUser.userKey = keyPair.publicKey;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceCreation(
            secondDevice.entry, authorDevice, tankerUser),
        Error::VerificationCode::InvalidUserKey);
  }
}

TEST_CASE("KeyPublishToDevice")
{
  TrustchainBuilder builder;

  auto const resultUser = builder.makeUser1("alice");
  auto const secondDevice = builder.makeDevice1("alice");
  auto const resourceId = make<Crypto::Mac>("mac");
  auto const symmetricKey = make<Crypto::SymmetricKey>("symmetric key");
  auto const kp2d = builder.shareToDevice(
      secondDevice.device, resultUser.user, resourceId, symmetricKey);
  auto kp2dEntry = blockToUnverifiedEntry(kp2d.front());
  auto const targetUser = secondDevice.user;
  auto authorDevice = secondDevice.device.asTankerDevice();

  SUBCASE("should reject an incorrectly signed KeyPublishToDevice")
  {
    kp2dEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToDevice(kp2dEntry, authorDevice, targetUser),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a keyPublishToDevice to a recipient with a user key")
  {
    auto const deviceV3 = builder.makeDevice3("alice");
    auto const targetUserUpdated = deviceV3.user;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToDevice(
            kp2dEntry, authorDevice, targetUserUpdated),
        Error::VerificationCode::InvalidUserKey);
  }

  SUBCASE("should reject a KeyPublishToDevice from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToDevice(kp2dEntry, authorDevice, targetUser),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid KeyPublishToDevice")
  {
    CHECK_NOTHROW(
        Verif::verifyKeyPublishToDevice(kp2dEntry, authorDevice, targetUser));
  }
}

TEST_CASE("KeyPublishToUser")
{
  TrustchainBuilder builder;

  auto const resultUser = builder.makeUser3("alice");
  auto const secondDevice = builder.makeDevice3("alice");
  auto const resourceId = make<Crypto::Mac>("mac");
  auto const symmetricKey = make<Crypto::SymmetricKey>("symmetric key");
  auto const kp2u = builder.shareToUser(
      secondDevice.device, resultUser.user, resourceId, symmetricKey);
  auto kp2uEntry = blockToUnverifiedEntry(kp2u);
  auto authorDevice = secondDevice.device.asTankerDevice();

  SUBCASE("Should reject an incorrectly signed KeyPublishToUser")
  {
    kp2uEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToUser(kp2uEntry, authorDevice),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a KeyPublishToUser from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToUser(kp2uEntry, authorDevice),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid KeyPublishToUser")
  {
    CHECK_NOTHROW(Verif::verifyKeyPublishToUser(kp2uEntry, authorDevice));
  }
}

TEST_CASE("KeyPublishToProvisionalUser")
{
  TrustchainBuilder builder;

  auto const user = builder.makeUser3("alice");
  auto const device = user.user.devices.front();

  auto const appPublicSignatureKey = make<Crypto::PublicSignatureKey>("app sig key");
  auto const tankerPublicSignatureKey = make<Crypto::PublicSignatureKey>("tanker sig key");
  auto const resourceId = make<Crypto::Mac>("mac");
  auto const twoTimesSealedSymmetricKey =
      make<Crypto::TwoTimesSealedSymmetricKey>(
          "two times sealed symmetric key");
  auto const blockGenerator = builder.makeBlockGenerator(device);
  auto const block = Serialization::deserialize<Block>(
      blockGenerator.keyPublishToProvisionalUser(appPublicSignatureKey,
                                                 tankerPublicSignatureKey,
                                                 resourceId,
                                                 twoTimesSealedSymmetricKey));
  auto authorDevice = device.asTankerDevice();

  auto kp2puEntry = blockToUnverifiedEntry(block);
  kp2puEntry.index = 3;

  SUBCASE("Should reject an incorrectly signed KeyPublishToUser")
  {
    kp2puEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToUser(kp2puEntry, authorDevice),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a KeyPublishToUser from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyKeyPublishToUser(kp2puEntry, authorDevice),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid KeyPublishToUser")
  {
    CHECK_NOTHROW(Verif::verifyKeyPublishToUser(kp2puEntry, authorDevice));
  }
}

TEST_CASE("KeyPublishToUserGroups")
{
  TrustchainBuilder builder;

  auto const resultUser = builder.makeUser3("alice");
  auto const secondDevice = builder.makeDevice3("alice");
  auto const resourceId = make<Crypto::Mac>("mac");
  auto const symmetricKey = make<Crypto::SymmetricKey>("symmetric key");
  auto const userBob = builder.makeUser3("bob");
  auto const resultGroup =
      builder.makeGroup(secondDevice.device, {resultUser.user, userBob.user});

  auto const kp2g = builder.shareToUserGroup(
      secondDevice.device, resultGroup.group, resourceId, symmetricKey);
  auto kp2gEntry = blockToUnverifiedEntry(kp2g);
  auto const targetGroup = resultGroup.group.tankerGroup;
  auto authorDevice = secondDevice.device.asTankerDevice();

  SUBCASE("should reject an incorrecly signed KeyPublishToUserGroups")
  {
    kp2gEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(Verif::verifyKeyPublishToUserGroup(
                                       kp2gEntry, authorDevice, targetGroup),
                                   Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a KeyPublishToUserGroup from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(Verif::verifyKeyPublishToUserGroup(
                                       kp2gEntry, authorDevice, targetGroup),
                                   Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid KeyPublishToUserGroups")
  {
    CHECK_NOTHROW(Verif::verifyKeyPublishToUserGroup(
        kp2gEntry, authorDevice, targetGroup));
  }
}

TEST_CASE("Verif DeviceRevocationV1")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser1("alice");
  auto secondDevice = builder.makeDevice1("alice");
  auto thirdDevice = builder.makeDevice1("alice");
  auto const authorDevice = secondDevice.device.asTankerDevice();
  auto const targetDevice = thirdDevice.device.asTankerDevice();

  auto const revokeBlock =
      builder.revokeDevice1(secondDevice.device, thirdDevice.device);

  deviceRevocationCommonChecks(blockToUnverifiedEntry(revokeBlock),
                               authorDevice,
                               targetDevice,
                               thirdDevice.user);

  SUBCASE("should reject a revocation for another user's device")
  {
    auto bob = builder.makeUser1("bob");
    auto bobDevice = builder.makeDevice1("bob");

    auto const revokeBobBlock =
        builder.revokeDevice1(secondDevice.device, bobDevice.device, true);
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(blockToUnverifiedEntry(revokeBobBlock),
                                      authorDevice,
                                      bobDevice.device.asTankerDevice(),
                                      secondDevice.user),
        Error::VerificationCode::InvalidUser);
  }

  SUBCASE("should reject a revocation whose user has a userKey v1")
  {
    auto fourthDevice = builder.makeDevice3("alice");
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(blockToUnverifiedEntry(revokeBlock),
                                      authorDevice,
                                      targetDevice,
                                      fourthDevice.user),
        Error::VerificationCode::InvalidUserKey);
  }
}

TEST_CASE("Verif DeviceRevocationV2")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser3("alice");
  auto secondDevice = builder.makeDevice3("alice");
  auto thirdDevice = builder.makeDevice3("alice");
  auto authorDevice = secondDevice.device.asTankerDevice();
  auto targetDevice = thirdDevice.device.asTankerDevice();
  auto aliceUser = builder.getUser("alice");
  auto const revokeBlock = builder.revokeDevice2(
      secondDevice.device, thirdDevice.device, *aliceUser);
  auto entry = blockToUnverifiedEntry(revokeBlock);

  auto bob = builder.makeUser1("bob");
  auto bobDevice = builder.makeDevice1("bob");
  auto bobOtherDevice = builder.makeDevice1("bob");
  auto const authorDeviceV1 = bobDevice.device.asTankerDevice();
  auto const targetDeviceV1 = bobOtherDevice.device.asTankerDevice();
  auto bobUser = builder.getUser("bob");
  auto const revokeBlockUserV1 =
      builder.revokeDevice2(bobDevice.device, bobOtherDevice.device, *bobUser);
  auto entryUserV1 = blockToUnverifiedEntry(revokeBlockUserV1);

  deviceRevocationCommonChecks(blockToUnverifiedEntry(revokeBlock),
                               authorDevice,
                               targetDevice,
                               thirdDevice.user);

  SUBCASE(
      "should reject a revocation whose user has no userKey when "
      "PreviousPublicEncryptionKey is not a zero array")
  {
    auto deviceRevocation = extractDeviceRevocation2(entryUserV1.action);
    deviceRevocation.previousPublicEncryptionKey[0]++;
    entryUserV1.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entryUserV1, authorDeviceV1, targetDeviceV1, bobOtherDevice.user),
        Error::VerificationCode::InvalidEncryptionKey);
  }

  SUBCASE(
      "should reject a revocation whose user has no userKey when the "
      "EncryptedKeyForPreviousUserKey is not a zero array")
  {
    auto deviceRevocation = extractDeviceRevocation2(entryUserV1.action);
    deviceRevocation.encryptedKeyForPreviousUserKey[0]++;
    entryUserV1.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entryUserV1, authorDeviceV1, targetDeviceV1, bobOtherDevice.user),
        Error::VerificationCode::InvalidUserKey);
  }

  SUBCASE("should reject a revocation for another user's device")
  {
    auto const revokeBlock = builder.revokeDevice2(
        secondDevice.device, bobOtherDevice.device, user.user, true);
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(blockToUnverifiedEntry(revokeBlock),
                                      authorDevice,
                                      targetDeviceV1,
                                      secondDevice.user),
        Error::VerificationCode::InvalidUser);
  }

  SUBCASE(
      "should reject a revocation whose user has a userKey when the "
      "previousEncryptedKey does not match the userKey")
  {
    auto deviceRevocation = extractDeviceRevocation2(entry.action);
    deviceRevocation.previousPublicEncryptionKey[0]++;
    entry.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entry, authorDevice, targetDevice, thirdDevice.user),
        Error::VerificationCode::InvalidEncryptionKey);
  }

  SUBCASE(
      "should reject a DeviceRevocation2 whose userKeys field does not have "
      "exactly one element per device")
  {
    auto deviceRevocation = extractDeviceRevocation2(entry.action);
    deviceRevocation.userKeys.erase(deviceRevocation.userKeys.begin());
    entry.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entry, authorDevice, targetDevice, thirdDevice.user),
        Error::VerificationCode::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceCreationV2 with a userKey fields that contains "
      "the target device of the revocation")
  {
    auto deviceRevocation = extractDeviceRevocation2(entry.action);
    deviceRevocation.userKeys.erase(deviceRevocation.userKeys.begin());
    auto sealedPrivateEncryptionKey =
        make<Crypto::SealedPrivateEncryptionKey>("encrypted private key");
    deviceRevocation.userKeys.push_back(EncryptedPrivateUserKey{
        thirdDevice.device.keys.deviceId, sealedPrivateEncryptionKey});
    entry.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entry, authorDevice, targetDevice, thirdDevice.user),
        Error::VerificationCode::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceRevocation whose userKeys fields has a device "
      "that does not belong to the author's devices")
  {
    auto deviceRevocation = extractDeviceRevocation2(entry.action);
    deviceRevocation.userKeys.erase(deviceRevocation.userKeys.begin());
    auto const sealedPrivateEncryptionKey =
        make<Crypto::SealedPrivateEncryptionKey>("encrypted private key");
    deviceRevocation.userKeys.push_back(EncryptedPrivateUserKey{
        bobDevice.device.keys.deviceId, sealedPrivateEncryptionKey});
    entry.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entry, authorDevice, targetDevice, thirdDevice.user),
        Error::VerificationCode::InvalidUserKeys);
  }

  SUBCASE(
      "should reject a DeviceRevocation whose userKeys fields has a duplicates")
  {
    auto deviceRevocation = extractDeviceRevocation2(entry.action);
    deviceRevocation.userKeys.erase(deviceRevocation.userKeys.begin());
    deviceRevocation.userKeys.push_back(*deviceRevocation.userKeys.begin());
    entry.action = DeviceRevocation{DeviceRevocation2{deviceRevocation}};

    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyDeviceRevocation(
            entry, authorDevice, targetDevice, thirdDevice.user),
        Error::VerificationCode::InvalidUserKeys);
  }
}

TEST_CASE("Verif UserGroupCreation")
{
  TrustchainBuilder builder;

  auto const resultUser = builder.makeUser3("alice");
  auto const secondDevice = builder.makeDevice3("alice");
  auto const resultGroup =
      builder.makeGroup(secondDevice.device, {resultUser.user});

  auto gcEntry = resultGroup.entry;
  auto authorDevice = secondDevice.device.asTankerDevice();

  SUBCASE("should reject an incorrectly signed UserGroupCreation")
  {
    gcEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a UserGroupCreation with invalid selfSignature")
  {
    auto userGroupCreation =
        mpark::get<UserGroupCreation>(gcEntry.action.variant());
    userGroupCreation.selfSignature[0]++;
    gcEntry.action = userGroupCreation;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a UserGroupCreation from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupCreation(gcEntry, authorDevice),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid UserGroupCreation")
  {
    CHECK_NOTHROW(Verif::verifyUserGroupCreation(gcEntry, authorDevice));
  }
}

TEST_CASE("Verif UserGroupAddition")
{
  TrustchainBuilder builder;

  auto const resultUser = builder.makeUser3("alice");
  auto const secondDevice = builder.makeDevice3("alice");
  auto const bobUser = builder.makeUser3("bob");
  auto const resultGroup =
      builder.makeGroup(secondDevice.device, {resultUser.user});
  auto const resultUserGroupAddition = builder.addUserToGroup(
      secondDevice.device, resultGroup.group, {bobUser.user});

  auto gaEntry = resultUserGroupAddition.entry;
  auto const& group = resultGroup.group.tankerGroup;
  auto authorDevice = secondDevice.device.asTankerDevice();

  SUBCASE("should reject an incorrectly signed UserGroupAddition")
  {
    gaEntry.signature[0]++;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, group),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE(
      "should reject a UserGroupAddition where previousGroupBlock is not the "
      "hash of last modification")
  {
    auto userGroupAddition =
        mpark::get<UserGroupAddition>(gaEntry.action.variant());
    userGroupAddition.previousGroupBlock[0]++;
    gaEntry.action = userGroupAddition;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, group),
        Error::VerificationCode::InvalidGroup);
  }

  SUBCASE("should reject a UserGroupAddition with invalid selfSignature")
  {
    auto userGroupAddition =
        mpark::get<UserGroupAddition>(gaEntry.action.variant());
    userGroupAddition.selfSignatureWithCurrentKey[0]++;
    gaEntry.action = userGroupAddition;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, group),
        Error::VerificationCode::InvalidSignature);
  }

  SUBCASE("should reject a UserGroupAddition from a revoked device")
  {
    authorDevice.revokedAtBlkIndex = authorDevice.createdAtBlkIndex + 1;
    CHECK_VERIFICATION_FAILED_WITH(
        Verif::verifyUserGroupAddition(gaEntry, authorDevice, group),
        Error::VerificationCode::InvalidAuthor);
  }

  SUBCASE("should accept a valid UserGroupAddition")
  {
    CHECK_NOTHROW(Verif::verifyUserGroupAddition(gaEntry, authorDevice, group));
  }
}
