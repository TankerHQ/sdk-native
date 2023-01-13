#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/KeyPublishAction.hpp>
#include <Tanker/Trustchain/Serialization.hpp>
#include <Tanker/Trustchain/UserAction.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain;

TEST_CASE("UpgradeRequired trustchain tests")
{
  SECTION("throw UpgradeRequired when deserializing a block with version 127")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedBlock = {
      // varint version (INVALID: 0x7F == 127)
      0x7F,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x01,
      // Rest doesn't matter, we shouldn't pass the version check
    };
    // clang-format on

    TANKER_CHECK_THROWS_WITH_CODE(getBlockNature(serializedBlock),
                                  Errors::Errc::UpgradeRequired);
  }

  SECTION(
      "throw UpgradeRequired when deserializing a key publish with nature 127")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedKeyPublishToUser = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature (INVALID: 0x7F == 127)
      0x7F,
      // Rest doesn't matter, we shouldn't pass the nature check
    };
    // clang-format on

    TANKER_CHECK_THROWS_WITH_CODE(
        deserializeKeyPublishAction(serializedKeyPublishToUser),
        Errors::Errc::UpgradeRequired);
  }

  SECTION("throw UpgradeRequired when deserializing a device with nature 127")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedDevice = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature (INVALID: 0x7F == 127)
      0x7F,
      // Rest doesn't matter, we shouldn't pass the nature check
    };
    // clang-format on

    TANKER_CHECK_THROWS_WITH_CODE(deserializeUserAction(serializedDevice),
                                  Errors::Errc::UpgradeRequired);
  }

  SECTION("throw UpgradeRequired when deserializing a group with nature 127")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedUserGroupCreation = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature (INVALID: 0x7F == 127)
      0x7F,
      // Rest doesn't matter, we shouldn't pass the nature check
    };
    // clang-format on

    TANKER_CHECK_THROWS_WITH_CODE(
        deserializeGroupAction(serializedUserGroupCreation),
        Errors::Errc::UpgradeRequired);
  }
}
