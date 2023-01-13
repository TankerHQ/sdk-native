#include <Tanker/Crypto/Padding.hpp>

#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <range/v3/view/iota.hpp>
#include <range/v3/view/zip.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;

TEST_CASE("Padding utilities tests")
{
  SECTION("padme returns the right values")
  {
    CHECK(Padding::padme(0) == 0);
    CHECK(Padding::padme(1) == 0);

    CHECK(Padding::padme(2) == 2);
    CHECK(Padding::padme(9) == 10);
    CHECK(Padding::padme(20) == 20);
    CHECK(Padding::padme(42) == 44);
    CHECK(Padding::padme(666) == 672);
    CHECK(Padding::padme(1999) == 2048);
  }

  SECTION("paddedFromClearSize returns the right values")
  {
    CHECK(Padding::paddedFromClearSize(0, std::nullopt) ==
          Padding::minimalPadding() + 1);
    // padme(20) == 20
    CHECK(Padding::paddedFromClearSize(20, std::nullopt) ==
          Padding::padme(20) + 1);
    CHECK(Padding::paddedFromClearSize(21, std::nullopt) ==
          Padding::padme(21) + 1);

    CHECK(Padding::paddedFromClearSize(0, Padding::Off) == 2);
    CHECK(Padding::paddedFromClearSize(1, Padding::Off) == 2);
    CHECK(Padding::paddedFromClearSize(130, Padding::Off) == 130 + 1);

    CHECK(Padding::paddedFromClearSize(0, 2) == 2 + 1);
    CHECK(Padding::paddedFromClearSize(2, 2) == 2 + 1);
    CHECK(Padding::paddedFromClearSize(10, 20) == 20 + 1);
    CHECK(Padding::paddedFromClearSize(20, 20) == 20 + 1);
  }

  SECTION("padClearData pads the data with a minimum padding")
  {
    auto const trueAsBytes = make_buffer("true");
    auto const actual = Padding::padClearData(trueAsBytes, std::nullopt);
    auto const expected = std::vector<uint8_t>{
        0x74, 0x72, 0x75, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(actual == expected);
  }

  SECTION("padClearData pads an empty array")
  {
    auto const empty = make_buffer("");
    auto const actual = Padding::padClearData(empty, std::nullopt);
    auto const expected = std::vector<uint8_t>{
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(actual == expected);
  }

  SECTION("padClearData uses the padme algorithm")
  {
    auto const empty = std::vector<uint8_t>{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10};
    auto const actual = Padding::padClearData(empty, std::nullopt);
    auto const expected = std::vector<uint8_t>{0x00,
                                               0x01,
                                               0x02,
                                               0x03,
                                               0x04,
                                               0x05,
                                               0x06,
                                               0x07,
                                               0x08,
                                               0x09,
                                               0x10,
                                               0x80,
                                               0x00};
    CHECK(actual == expected);
  }

  SECTION("unpaddedSize throws if no 0x80 or followed by non 0x00 bytes")
  {
    for (auto const& data : {{},
                             make_buffer("this data is a test data"),
                             {0x74, 0x72, 0x75, 0x65},
                             {0x74, 0x72, 0x75, 0x65, 0x00, 0x00, 0x00},
                             {0x74, 0x72, 0x75, 0x65, 0x80, 0x42},
                             {0x74, 0x72, 0x75, 0x65, 0x80, 0x42, 0x00},
                             {0x74, 0x72, 0x75, 0x65, 0x80, 0x00, 0x42}})
      TANKER_CHECK_THROWS_WITH_CODE(Padding::unpaddedSize(data),
                                    Errors::Errc::DecryptionFailed);
  }

  SECTION("unpaddedSize should return the right values")
  {
    std::vector<std::vector<uint8_t>> const samples = {
        {0x80},
        {0x74, 0x72, 0x75, 0x65, 0x80},
        {0x74, 0x72, 0x75, 0x65, 0x80, 0x00, 0x00},
        {0x74, 0x72, 0x75, 0x65, 0x80, 0x00, 0x00, 0x80, 0x00},
    };

    auto const expectations = {
        0u,
        4u,
        4u,
        7u,
    };

    for (auto const [i, data, expected] :
         ranges::views::zip(ranges::views::iota(0), samples, expectations))
    {
      // extra assignation required by doctest/clang to allow the capture
      auto const index = i;
      CAPTURE(index);

      auto const actual = Padding::unpaddedSize(data);
      CHECK(actual == expected);
    }
  }
}
