#include <doctest.h>

#include <Tanker/Actions/KeyPublishToProvisionalUser.hpp>
#include <Tanker/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Actions/UserGroupAddition.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/GroupId.hpp>

#include <Helpers/Buffers.hpp>

using namespace Tanker;

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
