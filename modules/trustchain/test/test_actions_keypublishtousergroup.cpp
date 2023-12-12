#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Buffers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("KeyPublishToUserGroup serialization test vectors")
{
  SECTION("it should serialize/deserialize a KeyPublishToUserGroup")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedKeyPublishToUserGroup = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x0b,
      // varint payload size
      0x80, 0x01,
      // recipient
      0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x75, 0x73,
      0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // resourceId
      0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x63,
      0x00, 0x00, 0x00, 0x00,
      // key
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65,
      0x79, 0x2e, 0x2e, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // author
      0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // signature
      0x73, 0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    auto const trustchainId = make<TrustchainId>("trustchain id");
    auto const author = make<Crypto::Hash>("author");
    auto const signature = make<Crypto::Signature>("sig");

    auto const recipientPublicEncryptionKey = make<Crypto::PublicEncryptionKey>("recipient user");
    auto const resourceId = make<Crypto::SimpleResourceId>("resource mac");
    auto const key = make<Crypto::SealedSymmetricKey>("encrypted key...");
    auto const hash = mgs::base64::decode<Crypto::Hash>("IdCaAoqJZw+0M1YDbfgZ1E1AcHk4sJqvKbRxiHqCIQI=");
    KeyPublishToUserGroup const kp(
        trustchainId, recipientPublicEncryptionKey, resourceId, key, author, hash, signature);

    CHECK(Serialization::serialize(kp) == serializedKeyPublishToUserGroup);
    CHECK(Serialization::deserialize<KeyPublishToUserGroup>(serializedKeyPublishToUserGroup) == kp);
  }
}
