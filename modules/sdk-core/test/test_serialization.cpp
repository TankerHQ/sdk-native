#include <doctest.h>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/DeviceRevocation.hpp>
#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Actions/KeyPublishToProvisionalUser.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Actions/KeyPublishToUserGroup.hpp>
#include <Tanker/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Actions/UserGroupAddition.hpp>
#include <Tanker/Actions/UserGroupCreation.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/GroupId.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

TEST_CASE("it should serialize/deserialize a TrustchainCreation")
{
  TrustchainCreation before;
  before.publicSignatureKey =
      make<Crypto::PublicSignatureKey>("my signature key");

  TrustchainCreation const after =
      Serialization::deserialize<TrustchainCreation>(
          Serialization::serialize(before));

  CHECK(before == after);
}

TEST_CASE("it should deserialize a DeviceCreation v1")
{
  std::vector<uint8_t> const serializedDevice = {
      // clang-format off
      // ephemeral public key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation signature
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      // clang-format on
  };

  DeviceCreation1 expected{};
  expected.ephemeralPublicSignatureKey =
      make<Crypto::PublicSignatureKey>("eph pub key");
  expected.userId = make<Trustchain::UserId>("user id");
  expected.delegationSignature = make<Crypto::Signature>("delegation sig");
  expected.publicSignatureKey =
      make<Crypto::PublicSignatureKey>("public signature key");
  expected.publicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("public enc key");

  auto const actual =
      Serialization::deserialize<DeviceCreation1>(serializedDevice);

  CHECK(actual == expected);
}

TEST_CASE("it should deserialize a DeviceCreation v2 into a DeviceCreation v1")
{
  std::vector<uint8_t> const serializedDevice = {
      // clang-format off
      // last reset
      0x72, 0x65, 0x73, 0x65, 0x74, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // ephemeral public signature key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation signature
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      // clang-format on
  };

  DeviceCreation1 expected{};
  expected.ephemeralPublicSignatureKey =
      make<Crypto::PublicSignatureKey>("eph pub key");
  expected.userId = make<Trustchain::UserId>("user id");
  expected.delegationSignature = make<Crypto::Signature>("delegation sig");
  expected.publicSignatureKey =
      make<Crypto::PublicSignatureKey>("public signature key");
  expected.publicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("public enc key");

  auto const actual = Serialization::deserialize<DeviceCreation1>(
      gsl::make_span(serializedDevice).subspan(Crypto::Hash::arraySize));

  CHECK(actual == expected);
}

TEST_CASE("it should serialize/deserialize a DeviceCreation v3")
{
  std::vector<uint8_t> const serializedDevice = {
      // clang-format off
      // eph pub key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation sig
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public enc key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user pub enc key
      0x75, 0x73, 0x65, 0x72, 0x20, 0x70, 0x75, 0x62, 0x20, 0x65, 0x6e, 0x63,
      0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // key
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // IsGhostDevice
      0x01,
      // clang-format on
  };

  DeviceCreation3 expected{};
  expected.ephemeralPublicSignatureKey =
      make<Crypto::PublicSignatureKey>("eph pub key");
  expected.userId = make<Trustchain::UserId>("user id");
  expected.delegationSignature = make<Crypto::Signature>("delegation sig");
  expected.publicSignatureKey =
      make<Crypto::PublicSignatureKey>("public signature key");
  expected.publicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("public enc key");

  expected.userKeyPair = UserKeyPair{
      make<Crypto::PublicEncryptionKey>("user pub enc key"),
      make<Crypto::SealedPrivateEncryptionKey>("key"),
  };

  expected.isGhostDevice = true;

  auto const actual =
      Serialization::deserialize<DeviceCreation3>(serializedDevice);

  CHECK_EQ(actual, expected);
  CHECK_EQ(Serialization::serialize(expected), serializedDevice);
}

TEST_CASE("it should serialize/deserialize a KeyPublishToDevice")
{
  KeyPublishToDevice before;
  before.recipient = make<DeviceId>("recipient device");
  before.mac = make<Crypto::Mac>("resource mac");
  before.key = make<Crypto::EncryptedSymmetricKey>("encrypted key ..");

  KeyPublishToDevice const after =
      deserializeKeyPublishToDevice(Serialization::serialize(before));

  CHECK(before == after);
}

TEST_CASE("it should serialize/deserialize a KeyPublishToUser")
{
  KeyPublishToUser before;
  before.recipientPublicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("recipient user");
  before.mac = make<Crypto::Mac>("resource mac");
  before.key = make<Crypto::SealedSymmetricKey>("encrypted key...");

  KeyPublishToUser const after =
      deserializeKeyPublishToUser(Serialization::serialize(before));

  CHECK(before == after);
}

TEST_CASE("it should serialize/deserialize a test vector KeyPublishToUser")
{
  auto const payload = std::vector<uint8_t>{
      0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x75, 0x73,
      0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x65, 0x73, 0x6f,
      0x75, 0x72, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x63, 0x00, 0x00, 0x00, 0x00,
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65,
      0x79, 0x2e, 0x2e, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  KeyPublishToUser expected;
  expected.recipientPublicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("recipient user");
  expected.mac = make<Crypto::Mac>("resource mac");
  expected.key = make<Crypto::SealedSymmetricKey>("encrypted key...");

  auto const actual = deserializeKeyPublishToUser(payload);

  CHECK(actual == expected);
}

TEST_CASE(
    "it should serialize/deserialize a test vector KeyPublishToProvisionalUser")
{
  // clang-format off
  auto const payload = std::vector<uint8_t>{
      // app public signature key
      0x61, 0x70, 0x70, 0x20, 0x70, 0x75, 0x62, 0x20, 0x73, 0x69, 0x67, 0x6e,
      0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // tanker public signature key
      0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70, 0x75, 0x62, 0x20, 0x73,
      0x69, 0x67, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // resource id
      0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x63,
      0x00, 0x00, 0x00, 0x00,
      // key
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65,
      0x79, 0x2e, 0x2e, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  KeyPublishToProvisionalUser keyPublish;
  keyPublish.appPublicSignatureKey =
      make<Crypto::PublicSignatureKey>("app pub sign key");
  keyPublish.tankerPublicSignatureKey =
      make<Crypto::PublicSignatureKey>("tanker pub sign key");
  keyPublish.resourceId = make<ResourceId>("resource mac");
  keyPublish.key = make<Crypto::TwoTimesSealedSymmetricKey>("encrypted key...");

  CHECK(Serialization::serialize(keyPublish) == payload);
  CHECK(deserializeKeyPublishToProvisionalUser(payload) == keyPublish);
}

TEST_CASE("it should serialize/deserialize a KeyPublishToUserGroup")
{
  KeyPublishToUserGroup keyPublish;
  keyPublish.recipientPublicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("recipient group");
  keyPublish.resourceId = make<Crypto::Mac>("resource mac");
  keyPublish.key = make<Crypto::SealedSymmetricKey>("encrypted key...");

  auto const payload = std::vector<uint8_t>{
      0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x67, 0x72,
      0x6f, 0x75, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x65, 0x73, 0x6f,
      0x75, 0x72, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x63, 0x00, 0x00, 0x00, 0x00,
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65,
      0x79, 0x2e, 0x2e, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  CHECK(Serialization::serialize(keyPublish) == payload);
  CHECK(deserializeKeyPublishToUserGroup(payload) == keyPublish);
}

TEST_CASE("it should serialize/deserialize a Block")
{
  Block before;
  before.trustchainId = make<Trustchain::TrustchainId>("the trustchain ID !");
  before.index = 12345;
  before.author = make<Crypto::Hash>("block author");
  before.payload = std::vector<uint8_t>{10, 11, 12, 88, 191, 16};
  before.signature = make<Crypto::Signature>("this is a signature");

  Block const after =
      Serialization::deserialize<Block>(Serialization::serialize(before));

  CHECK(before == after);
}

TEST_CASE("it should serialize/deserialize a DeviceRevocation V1")
{
  DeviceRevocation1 before{};
  before.deviceId = make<DeviceId>("the device ID !");

  auto const after = Serialization::deserialize<DeviceRevocation1>(
      Serialization::serialize(before));

  CHECK(before == after);
}

TEST_CASE("it should serialize/deserialize a DeviceRevocation V2")
{
  DeviceRevocation2 before;
  before.deviceId = make<DeviceId>("the device ID !");
  before.publicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("the new user key");
  before.previousPublicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("the previous user key");
  before.encryptedKeyForPreviousUserKey =
      make<Crypto::SealedPrivateEncryptionKey>("enc for previous user");
  before.userKeys.push_back(
      EncryptedPrivateUserKey{make<DeviceId>("enc pub key recipient"),
                              make<Crypto::SealedPrivateEncryptionKey>(
                                  "encrypted magical private key")});

  auto const after = Serialization::deserialize<DeviceRevocation2>(
      Serialization::serialize(before));
  CHECK(before == after);
}

TEST_CASE("it should deserialize a device revocation v1")
{
  auto const payload = std::vector<uint8_t>{
      0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20,
      0x49, 0x44, 0x20, 0x21, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0};

  DeviceRevocation1 expected{};
  expected.deviceId = make<DeviceId>("the device ID !");

  auto const actual = Serialization::deserialize<DeviceRevocation1>(payload);

  CHECK(actual == expected);
}

TEST_CASE("it should deserialize a device revocation v2")
{
  // clang-format off
  auto const payload = std::vector<uint8_t>{
      // device_id
      0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85, 0xab, 0x9d, 0xbe, 0x3f,
      0xdb, 0x57, 0x2b, 0x71, 0x6c, 0x0d, 0xa1, 0xa3, 0xad, 0xb8, 0x86, 0x9b,
      0x39, 0x58, 0xcb, 0x00, 0xfa, 0x31, 0x5d, 0x87,
      // public_encryption_key
      0xe4, 0x78, 0xea, 0x52, 0x7a, 0x28, 0x21, 0x45, 0x6b, 0x51, 0x99, 0xf7,
      0xa8, 0x6e, 0x20, 0x49, 0xb4, 0x75, 0x07, 0xcc, 0x8b, 0x98, 0x98, 0x3d,
      0xe0, 0xd6, 0xed, 0x04, 0xd2, 0xcf, 0xf1, 0xaf,
      // previous_public_encryption_key
      0xaa, 0xaa, 0xea, 0x52, 0x7a, 0x28, 0x21, 0x45, 0x6b, 0x51, 0x99, 0xf7,
      0xa8, 0x6e, 0x20, 0x49, 0xb4, 0x75, 0xaa, 0xcc, 0xaa, 0x98, 0x98, 0x3d,
      0xe0, 0xd6, 0xed, 0x04, 0xd2, 0xcf, 0xf1, 0xaa,
      // encrypted_key_for_previous_user_key
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      // encrypted_keys_for_devices[]
      0x01,
      // device_id
      0xd0, 0xa8, 0x9e, 0xff, 0x7d, 0x59, 0x48, 0x3a, 0xee, 0x7c, 0xe4, 0x99,
      0x49, 0x4d, 0x1c, 0xd7, 0x87, 0x54, 0x41, 0xf5, 0xba, 0x51, 0xd7, 0x65,
      0xbf, 0x91, 0x45, 0x08, 0x03, 0xf1, 0xe9, 0xc7,
      // encrypted_private_encryption_key
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
  };

  DeviceRevocation2 expected;
  expected.deviceId = make<DeviceId>({
      0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85, 0xab, 0x9d, 0xbe, 0x3f,
      0xdb, 0x57, 0x2b, 0x71, 0x6c, 0x0d, 0xa1, 0xa3, 0xad, 0xb8, 0x86, 0x9b,
      0x39, 0x58, 0xcb, 0x00, 0xfa, 0x31, 0x5d, 0x87});
  expected.publicEncryptionKey = make<Crypto::PublicEncryptionKey>({
      0xe4, 0x78, 0xea, 0x52, 0x7a, 0x28, 0x21, 0x45, 0x6b, 0x51, 0x99, 0xf7,
      0xa8, 0x6e, 0x20, 0x49, 0xb4, 0x75, 0x07, 0xcc, 0x8b, 0x98, 0x98, 0x3d,
      0xe0, 0xd6, 0xed, 0x04, 0xd2, 0xcf, 0xf1, 0xaf});
  expected.previousPublicEncryptionKey = make<Crypto::PublicEncryptionKey>({
      0xaa, 0xaa, 0xea, 0x52, 0x7a, 0x28, 0x21, 0x45, 0x6b, 0x51, 0x99, 0xf7,
      0xa8, 0x6e, 0x20, 0x49, 0xb4, 0x75, 0xaa, 0xcc, 0xaa, 0x98, 0x98, 0x3d,
      0xe0, 0xd6, 0xed, 0x04, 0xd2, 0xcf, 0xf1, 0xaa});
  expected.encryptedKeyForPreviousUserKey =
    make<Crypto::SealedPrivateEncryptionKey>({
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69});
  expected.userKeys.push_back(EncryptedPrivateUserKey{make<DeviceId>({
      0xd0, 0xa8, 0x9e, 0xff, 0x7d, 0x59, 0x48, 0x3a, 0xee, 0x7c, 0xe4, 0x99,
      0x49, 0x4d, 0x1c, 0xd7, 0x87, 0x54, 0x41, 0xf5, 0xba, 0x51, 0xd7, 0x65,
      0xbf, 0x91, 0x45, 0x08, 0x03, 0xf1, 0xe9, 0xc7
      }),
      make<Crypto::SealedPrivateEncryptionKey>({
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69})});
  // clang-format on

  auto const actual = Serialization::deserialize<DeviceRevocation2>(payload);

  CHECK(actual == expected);
}

TEST_CASE("it should serialize/deserialize a UserGroupCreation")
{
  UserGroupCreation ugc;

  ugc.publicSignatureKey = make<Crypto::PublicSignatureKey>("pub sig key");
  ugc.publicEncryptionKey = make<Crypto::PublicEncryptionKey>("pub enc key");
  ugc.encryptedPrivateSignatureKey =
      make<Crypto::SealedPrivateSignatureKey>("encrypted priv sig key");
  ugc.encryptedGroupPrivateEncryptionKeysForUsers = {
      {
          make<Crypto::PublicEncryptionKey>("pub user key"),
          make<Crypto::SealedPrivateEncryptionKey>("encrypted group priv key"),
      },
      {
          make<Crypto::PublicEncryptionKey>("second pub user key"),
          make<Crypto::SealedPrivateEncryptionKey>(
              "second encrypted group priv key"),
      }};
  ugc.selfSignature = make<Crypto::Signature>("self signature");

  // clang-format off
  auto const payload = std::vector<uint8_t>{
    // public signature key
    0x70, 0x75, 0x62, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // public encryption key
    0x70, 0x75, 0x62, 0x20,
    0x65, 0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // encrypted group private signature key
    0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
    0x64, 0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b,
    0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // varint
    0x02,
    // public user encryption key 1
    0x70, 0x75, 0x62,
    0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    // encrypted group private encryption key 1
    0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
    0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69,
    0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
    // public user encryption key 2
    0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x20,
    0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // encrypted group private encryption key 2
    0x73, 0x65, 0x63,
    0x6f, 0x6e, 0x64, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
    0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69, 0x76,
    0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    // self signature
    0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69,
    0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  CHECK(Serialization::serialize(ugc) == payload);
  CHECK(deserializeUserGroupCreation(payload) == ugc);
}

TEST_CASE("it should serialize/deserialize a UserGroupAddition")
{
  UserGroupAddition ugc;

  ugc.groupId = make<GroupId>("group id");
  ugc.previousGroupBlock = make<Crypto::Hash>("prev group block");
  ugc.encryptedGroupPrivateEncryptionKeysForUsers = {
      {
          make<Crypto::PublicEncryptionKey>("pub user key"),
          make<Crypto::SealedPrivateEncryptionKey>("encrypted group priv key"),
      },
      {
          make<Crypto::PublicEncryptionKey>("second pub user key"),
          make<Crypto::SealedPrivateEncryptionKey>(
              "second encrypted group priv key"),
      }};
  ugc.selfSignatureWithCurrentKey = make<Crypto::Signature>("self signature");

  // clang-format off
  auto const payload = std::vector<uint8_t>{
    // group id
    0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // previous group block
    0x70, 0x72, 0x65, 0x76, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x62,
    0x6c, 0x6f, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // varint
    0x02,
    // public user encryption key 1
    0x70, 0x75, 0x62,
    0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    // encrypted group private encryption key 1
    0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
    0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69,
    0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
    // public user encryption key 2
    0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x20,
    0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // encrypted group private encryption key 2
    0x73, 0x65, 0x63,
    0x6f, 0x6e, 0x64, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
    0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69, 0x76,
    0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    // self signature
    0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69,
    0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  CHECK(Serialization::serialize(ugc) == payload);
  CHECK(deserializeUserGroupAddition(payload) == ugc);
}

TEST_CASE("should serialize/deserialize a ProvisionalIdentityClaim")
{
  ProvisionalIdentityClaim pic;

  pic.userId = make<Trustchain::UserId>("the user id");
  pic.appSignaturePublicKey =
      make<Crypto::PublicSignatureKey>("the app sig pub key");
  pic.tankerSignaturePublicKey =
      make<Crypto::PublicSignatureKey>("the tanker sig pub key");
  pic.authorSignatureByAppKey =
      make<Crypto::Signature>("the author sig by app key");
  pic.authorSignatureByTankerKey =
      make<Crypto::Signature>("the author sig by tanker key");
  pic.userPublicEncryptionKey =
      make<Crypto::PublicEncryptionKey>("user pub key");
  pic.encryptedPrivateKeys =
      make<ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>(
          "both encrypted private keys");

  auto const payload = std::vector<uint8_t>{
      // clang-format off
      // UserID
      0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // AppProvisionalIdentitySignaturePublicKey
      0x74, 0x68, 0x65, 0x20,
      0x61, 0x70, 0x70, 0x20, 0x73, 0x69, 0x67, 0x20, 0x70, 0x75, 0x62, 0x20,
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // TankerProvisionalIdentitySignaturePublicKey
      0x74, 0x68, 0x65, 0x20, 0x74, 0x61, 0x6e, 0x6b,
      0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // AuthorSignatureByAppKey
      0x74, 0x68, 0x65, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x20, 0x73,
      0x69, 0x67, 0x20, 0x62, 0x79, 0x20, 0x61, 0x70, 0x70, 0x20, 0x6b, 0x65,
      0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // AuthorSignatureByTankerKey
      0x74, 0x68, 0x65, 0x20, 0x61, 0x75, 0x74, 0x68,
      0x6f, 0x72, 0x20, 0x73, 0x69, 0x67, 0x20, 0x62, 0x79, 0x20, 0x74, 0x61,
      0x6e, 0x6b, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // RecipientUserPublicKey
      0x75, 0x73, 0x65, 0x72, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // EncryptedProvisionalIdentityPrivateKeys
      0x62, 0x6f, 0x74, 0x68,
      0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x70,
      0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x73, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // clang-format on
  };

  CHECK(Serialization::serialize(pic) == payload);
  CHECK(deserializeProvisionalIdentityClaim(payload) == pic);
}
