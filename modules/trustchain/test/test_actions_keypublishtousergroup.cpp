#include <Tanker/Trustchain/Actions/KeyPublishToUserGroup.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("KeyPublishToUserGroup tests")
{
  Crypto::PublicEncryptionKey const publicEncryptionKey{};
  ResourceId const resourceId{};
  Crypto::SealedSymmetricKey const key{};
  KeyPublishToUserGroup kp(publicEncryptionKey, resourceId, key);

  CHECK(kp.nature() == Nature::KeyPublishToUserGroup);
}

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a KeyPublishToUserGroup")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedKeyPublishToUserGroup = {
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
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // clang-format on

    auto const recipientPublicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("recipient user");
    auto const resourceId = make<ResourceId>("resource mac");
    auto const key = make<Crypto::SealedSymmetricKey>("encrypted key...");
    KeyPublishToUserGroup const kp(recipientPublicEncryptionKey, resourceId, key);

    CHECK(Serialization::serialize(kp) == serializedKeyPublishToUserGroup);
    CHECK(Serialization::deserialize<KeyPublishToUserGroup>(
              serializedKeyPublishToUserGroup) == kp);
  }
}