#include <doctest.h>

#include <algorithm>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Seal.hpp>
#include <Tanker/Serialization/Varint.hpp>

using namespace Tanker;

TEST_CASE("Inflate seal")
{
  std::vector<uint8_t> const symKeyContent(32);
  Crypto::SymmetricKey symKey(gsl::make_span(symKeyContent));

  SUBCASE("Empty seal throws")
  {
    std::vector<uint8_t> const sealContent = {};
    CHECK_THROWS_AS(Seal::inflate(sealContent), Error::DecryptFailed);
  }

  SUBCASE("Invalid seal throw")
  {
    std::vector<uint8_t> const sealContent = {0};
    CHECK_THROWS(Seal::inflate(sealContent));
  }

  SUBCASE("Version is right")
  {
    std::vector<uint8_t> const sealContent = {3, 0};
    auto seal = Seal::inflate(sealContent);
    CHECK(seal.version() == Seal::defaultSealVersion());
  }

  SUBCASE("Can extract a symmetricKey without empty ranges")
  {
    // 32 of symmetricKey + 1 byte of version + 1 byte size of emptyRanges (0).
    std::vector<uint8_t> values(34);
    auto seal = Seal::inflate(values);
    CHECK(seal.keys().size() == 1);
    CHECK(seal.keys()[0] == symKey);
  }

  SUBCASE("Can extract a symmetricKey with empty ranges")
  {
    // 32 of symmetricKey + 1 byte of version + 1 byte size of emptyRanges (2) +
    // 2 bytes for the range.
    std::vector<uint8_t> values(36);
    // Size of emptyRanges
    values[1] = 2;
    auto seal = Seal::inflate(values);
    CHECK(seal.keys().size() == 1);
    CHECK(seal.keys()[0] == symKey);
  }

  SUBCASE("Throws when the key is truncated")
  {
    std::vector<uint8_t> values(45);
    CHECK_THROWS(Seal::inflate(values));
  }

  SUBCASE("Empty emptyRanges does not throw")
  {
    std::vector<uint8_t> const sealContent = {0, 0};
    auto seal = Seal::inflate(sealContent);
    CHECK(seal.emptyRanges().empty());
  }

  SUBCASE("Invalid emptyRanges")
  {
    std::vector<uint8_t> const sealContent = {0, 1};
    CHECK_THROWS(Seal::inflate(sealContent));
  }

  SUBCASE("EmptyRanges is not in pairs")
  {
    std::vector<uint8_t> const sealContent = {0, 1, 1};
    CHECK_THROWS(Seal::inflate(sealContent));
  }

  SUBCASE("EmptyRanges is too short")
  {
    std::vector<uint8_t> const sealContent = {0, 4, 1, 1};
    CHECK_THROWS(Seal::inflate(sealContent));
  }

  SUBCASE("A single pair can be extracted")
  {
    std::vector<uint8_t> const sealContent = {0, 2, 1, 1};
    auto seal = Seal::inflate(sealContent);
    CHECK(seal.emptyRanges().size() == 1);
    CHECK(seal.emptyRanges()[0] == Seal::Range(1, 1));
  }

  SUBCASE("Can extract multiple pairs")
  {
    std::vector<uint8_t> const sealContent = {0, 4, 1, 1, 3, 5};
    auto seal = Seal::inflate(sealContent);
    CHECK(seal.emptyRanges().size() == 2);
    CHECK(seal.emptyRanges()[0] == Seal::Range(1, 1));
    CHECK(seal.emptyRanges()[1] == Seal::Range(3, 5));
  }
  SUBCASE("Throws when the range is upside down")
  {
    std::vector<uint8_t> const sealContent = {0, 2, 4, 1};
    CHECK_THROWS(Seal::inflate(sealContent));
  }

  SUBCASE("Inflate full seal")
  {
    std::vector<uint8_t> sealContent = {0, 4, 1, 1, 3, 5};
    auto const key = Crypto::makeSymmetricKey();
    sealContent.insert(sealContent.end(), key.begin(), key.end());
    auto seal = Seal::inflate(sealContent);
    CHECK(seal.keys().size() == 1);
  }
}

TEST_CASE("splitRange")
{
  Seal seal;
  Seal::Range test{1, 1};
  Seal::Range test2{1, 3};

  SUBCASE("Does remove one range")
  {
    auto const res = seal.splitRange(test, 1);
    CHECK(res.empty());
  }

  SUBCASE("Does not remove when index is wrong")
  {
    auto const res = seal.splitRange(test, 0);
    CHECK(res.size() == 1);
  }

  SUBCASE("Updates the range if it is more than 1")
  {
    auto const res = seal.splitRange(test2, 1);
    CHECK(res.size() == 1);
    CHECK(res[0] == Seal::Range(2, 3));
  }

  SUBCASE("Updates the range when the index to remove is in the middle")
  {
    auto const res = seal.splitRange(test2, 2);
    CHECK(res.size() == 2);
    CHECK(res[0] == Seal::Range(1, 1));
    CHECK(res[1] == Seal::Range(3, 3));
  }
}

TEST_CASE("removeFromRanges")
{
  std::vector<uint8_t> sealContent{
      static_cast<uint8_t>(Seal::defaultSealVersion()), 4, 1, 3, 4, 4};
  auto const key = Crypto::makeSymmetricKey();
  sealContent.insert(sealContent.end(), key.begin(), key.end());
  Seal testSeal = Seal::inflate(sealContent);

  SUBCASE("Remove in the middle")
  {
    std::vector<uint64_t> indexes({2});
    testSeal.removeFromRanges(indexes);
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 3);
    CHECK(test[0] == Seal::Range(1, 1));
    CHECK(test[1] == Seal::Range(3, 3));
    CHECK(test[2] == Seal::Range(4, 4));
  }
  SUBCASE("Remove everything")
  {
    std::vector<uint64_t> indexes({1, 2, 3, 4, 5});
    testSeal.removeFromRanges(indexes);
    CHECK(testSeal.emptyRanges().empty());
  }

  SUBCASE("Remove nothing")
  {
    std::vector<uint64_t> indexes({0, 5});
    testSeal.removeFromRanges(indexes);
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 2);
    CHECK(test[0] == Seal::Range(1, 3));
    CHECK(test[1] == Seal::Range(4, 4));
  }

  SUBCASE("Seal size is right")
  {
    std::vector<uint64_t> indexes({1, 4});
    testSeal.removeFromRanges(indexes);
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 1);
    CHECK(test[0] == Seal::Range(2, 3));

    CHECK(testSeal.size() == key.arraySize + 4);
  }

  SUBCASE("Can serialize after a remove")
  {
    std::vector<uint64_t> indexes({1, 4});
    testSeal.removeFromRanges(indexes);
    CHECK_NOTHROW(testSeal.serialize());
  }
}

TEST_CASE("Update ranges after removing them")
{
  std::vector<uint8_t> sealContent = {
      static_cast<uint8_t>(Seal::defaultSealVersion()), 4, 1, 2, 4, 4};
  Seal testSeal = Seal::inflate(sealContent);

  SUBCASE("Does nothing with no empty ranges")
  {
    Seal emptySeal;
    std::vector<uint64_t> indexes({0, 5});
    emptySeal.updateRangesAfterRemove(indexes);
    CHECK(emptySeal.emptyRanges().empty());
  }

  SUBCASE("Updates ranges when 1 element is removed")
  {
    std::vector<uint64_t> indexes({0});
    testSeal.updateRangesAfterRemove(indexes);
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 2);
    CHECK(test[0] == Seal::Range(0, 1));
    CHECK(test[1] == Seal::Range(3, 3));
  }

  SUBCASE("Updates ranges with multiple elements")
  {
    std::vector<uint64_t> indexes({0, 1});
    testSeal.removeFromRanges(indexes);
    testSeal.updateRangesAfterRemove(indexes);
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 2);
    CHECK(test[0] == Seal::Range(0, 0));
    CHECK(test[1] == Seal::Range(2, 2));
  }

  SUBCASE("Updates ranges with multiple elements")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 4, 1, 3, 5, 5};
    Seal seal = Seal::inflate(sealContent);
    std::vector<uint64_t> indexes({0, 2});
    seal.removeFromRanges(indexes);
    seal.updateRangesAfterRemove(indexes);
    auto const test = seal.emptyRanges();
    CHECK(test.size() == 2);
    CHECK(test[0] == Seal::Range(0, 1));
    CHECK(test[1] == Seal::Range(3, 3));
  }
}

TEST_CASE("Emplace Range")
{
  std::vector<uint8_t> sealContent = {
      static_cast<uint8_t>(Seal::defaultSealVersion()), 4, 1, 2, 4, 4};
  Seal testSeal = Seal::inflate(sealContent);

  SUBCASE("Throws if range is not ordered")
  {
    CHECK_THROWS_AS(testSeal.emplaceRange({6, 5}), Error::InvalidArgument);
  }

  SUBCASE("Can emplace a range of 1")
  {
    testSeal.emplaceRange({6, 6});
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 3);
    CHECK(test[0] == Seal::Range(1, 2));
    CHECK(test[1] == Seal::Range(4, 4));
    CHECK(test[2] == Seal::Range(6, 6));
  }

  SUBCASE("Can emplace a range > 1")
  {
    testSeal.emplaceRange({6, 7});
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 3);
    CHECK(test[0] == Seal::Range(1, 2));
    CHECK(test[1] == Seal::Range(4, 4));
    CHECK(test[2] == Seal::Range(6, 7));
  }

  SUBCASE("Should merge ranges if there are concatenated")
  {
    testSeal.emplaceRange({5, 6});
    auto const test = testSeal.emptyRanges();
    CHECK(test.size() == 2);
    CHECK(test[0] == Seal::Range(1, 2));
    CHECK(test[1] == Seal::Range(4, 6));
  }

  SUBCASE("Seal size is right after emplace (add elements)")
  {
    testSeal.emplaceRange({6, 7});
    // The size expected is 8 (version + size of empty ranges + 3 * (empty
    // ranges))
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 7);
  }

  SUBCASE("Seal size is right after emplace (merge elements)")
  {
    testSeal.emplaceRange({5, 6});
    // The size expected is 8 (version + size of empty ranges + 2 * (empty
    // ranges))
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 5);
  }

  SUBCASE("Can serialize after emplace")
  {
    testSeal.emplaceRange({6, 7});
    CHECK_NOTHROW(testSeal.serialize());
  }
}

TEST_CASE("Serialize")
{
  SUBCASE("Can serialize empty seal")
  {
    Seal testSeal;
    CHECK_NOTHROW(testSeal.serialize());
  }

  SUBCASE("Can serialize non empty seal")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 0};
    auto testSeal = Seal::inflate(sealContent);
    CHECK_NOTHROW(testSeal.serialize());
  }

  SUBCASE("Serialize and inflates leads to the same seal")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 4, 1, 3, 4, 4};
    auto const key = Crypto::makeSymmetricKey();
    sealContent.insert(sealContent.end(), key.begin(), key.end());
    auto testSeal = Seal::inflate(sealContent);
    auto const serializedContent = testSeal.serialize();

    CHECK(std::equal(
        sealContent.begin(), sealContent.end(), serializedContent.begin()));
  }
}

TEST_CASE("Elements")
{
  SUBCASE("Size is right when empty")
  {
    Seal testSeal;
    CHECK(testSeal.nbElements() == 0);
  }

  SUBCASE("Size is right with only empty ranges")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 2, 0, 1};
    auto testSeal = Seal::inflate(sealContent);
    CHECK(testSeal.nbElements() == 2);
  }

  SUBCASE("Size is right with only keys")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 0};
    auto const key = Crypto::makeSymmetricKey();
    sealContent.insert(sealContent.end(), key.begin(), key.end());
    auto testSeal = Seal::inflate(sealContent);
    CHECK(testSeal.nbElements() == 1);
  }

  SUBCASE("Size is right")
  {
    std::vector<uint8_t> sealContent = {
        static_cast<uint8_t>(Seal::defaultSealVersion()), 2, 0, 1};
    auto const key = Crypto::makeSymmetricKey();
    sealContent.insert(sealContent.end(), key.begin(), key.end());
    sealContent.insert(sealContent.end(), key.begin(), key.end());
    auto testSeal = Seal::inflate(sealContent);
    CHECK(testSeal.nbElements() == 4);
  }
}

TEST_CASE("ChunkAt")
{
  std::vector<uint8_t> sealContent = {
      static_cast<uint8_t>(Seal::defaultSealVersion()), 2, 0, 1};
  auto const key = Crypto::makeSymmetricKey();
  sealContent.insert(sealContent.end(), key.begin(), key.end());
  auto testSeal = Seal::inflate(sealContent);

  SUBCASE("Throws if index is ouf of range")
  {
    CHECK_THROWS_AS(testSeal.chunkAt(3), Error::ChunkIndexOutOfRange);
  }

  SUBCASE("Can return an empty element")
  {
    CHECK(testSeal.chunkAt(1) == nonstd::nullopt);
  }

  SUBCASE("Can return a non empty element")
  {
    CHECK(testSeal.chunkAt(2) == key);
  }
}

TEST_CASE("Remove")
{
  std::vector<uint8_t> sealContent = {
      static_cast<uint8_t>(Seal::defaultSealVersion()), 2, 0, 1};
  auto const key = Crypto::makeSymmetricKey();
  sealContent.insert(sealContent.end(), key.begin(), key.end());
  Seal testSeal = Seal::inflate(sealContent);

  SUBCASE("Throws if an index is out of range")
  {
    std::vector<uint64_t> const indexes = {3};
    CHECK_THROWS_AS(testSeal.remove(indexes), Error::ChunkIndexOutOfRange);
  }

  SUBCASE("Can remove one element")
  {
    std::vector<uint64_t> const indexes = {2};
    testSeal.remove(indexes);
    CHECK(testSeal.nbElements() == 2);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 3);
  }

  SUBCASE("Can remove multiple elements")
  {
    std::vector<uint64_t> const indexes = {1, 2};
    testSeal.remove(indexes);
    CHECK(testSeal.nbElements() == 1);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 3);
  }

  SUBCASE("Can serialize after remove")
  {
    std::vector<uint64_t> const indexes = {1, 2};
    testSeal.remove(indexes);
    CHECK_NOTHROW(testSeal.serialize());
  }
}

TEST_CASE("Add chunk at")
{
  std::vector<uint8_t> sealContent = {
      static_cast<uint8_t>(Seal::defaultSealVersion()), 2, 0, 1};
  auto const key = Crypto::makeSymmetricKey();
  sealContent.insert(sealContent.end(), key.begin(), key.end());
  Seal testSeal = Seal::inflate(sealContent);

  SUBCASE("Can append chunk")
  {
    testSeal.addChunkAt(key, 3);
    CHECK(testSeal.nbElements() == 4);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 3 +
              2 * key.arraySize);
  }

  SUBCASE("Can replace already existing key")
  {
    testSeal.addChunkAt(key, 2);
    CHECK(testSeal.nbElements() == 3);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 3 +
              key.arraySize);
  }

  SUBCASE("Can replace a hole")
  {
    testSeal.addChunkAt(key, 1);
    CHECK(testSeal.nbElements() == 3);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 3 +
              2 * key.arraySize);
    CHECK(testSeal.emptyRanges()[0] == Seal::Range(0, 0));
  }

  SUBCASE("Can add chunk with holes")
  {
    testSeal.addChunkAt(key, 4);
    CHECK(testSeal.nbElements() == 5);
    CHECK(testSeal.size() ==
          Serialization::varint_size(Seal::defaultSealVersion()) + 5 +
              2 * key.arraySize);
    CHECK(testSeal.emptyRanges().size() == 2);
    CHECK(testSeal.emptyRanges()[0] == Seal::Range(0, 1));
    CHECK(testSeal.emptyRanges()[1] == Seal::Range(3, 3));
  }
}
