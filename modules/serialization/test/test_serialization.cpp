#include <Tanker/Serialization/Serialization.hpp>

#include <Tanker/Serialization/Errors/Errc.hpp>

#include <Helpers/Errors.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <utility>
#include <vector>

using namespace Tanker;
using namespace Tanker::Serialization;

namespace
{
struct Vec
{
  std::vector<std::uint8_t> buffer;
};

struct VecHolder
{
  std::uint8_t byte;
  Vec vec;
};

bool operator==(Vec const& lhs, Vec const& rhs) noexcept
{
  return lhs.buffer == rhs.buffer;
}

bool operator==(VecHolder const& lhs, VecHolder const& rhs) noexcept
{
  return std::tie(lhs.byte, lhs.vec) == std::tie(rhs.byte, rhs.vec);
}

std::size_t serialized_size(Vec const& v)
{
  return v.buffer.size() + 1;
}

std::size_t serialized_size(VecHolder const& vh)
{
  return serialized_size(vh.vec) + sizeof(vh.byte);
}

std::uint8_t* to_serialized(std::uint8_t* it, Vec const& v)
{
  // don't try this at home
  *it++ = static_cast<std::uint8_t>(v.buffer.size());
  return std::copy(v.buffer.begin(), v.buffer.end(), it);
}

std::uint8_t* to_serialized(std::uint8_t* it, VecHolder const& vh)
{
  *it++ = vh.byte;
  return serialize(it, vh.vec);
}

void from_serialized(SerializedSource& ss, Vec& v)
{
  auto const size = ss.read(1)[0];
  auto const sp = ss.read(size);
  v.buffer.reserve(sp.size());
  std::copy(sp.begin(), sp.end(), std::back_inserter(v.buffer));
}

void from_serialized(SerializedSource& ss, VecHolder& vh)
{
  vh.byte = ss.read(1)[0];
  vh.vec = deserialize<Vec>(ss);
}
}

TEST_CASE("serialized_size")
{
  SECTION("Vec")
  {
    Vec v;
    CHECK(Serialization::serialized_size(v) == 1);

    v.buffer.resize(10);
    CHECK(Serialization::serialized_size(v) == 11);
  }

  SECTION("VecHolder")
  {
    VecHolder vh;
    CHECK(Serialization::serialized_size(vh) == 2);

    vh.vec.buffer.resize(10);
    CHECK(Serialization::serialized_size(vh) == 12);
  }

  SECTION("vector<VecHolder>")
  {
    std::vector<VecHolder> vhs(3);
    CHECK(Serialization::serialized_size(vhs) == 1 + 3 * Serialization::serialized_size(vhs.front()));

    vhs.front().vec.buffer.resize(10);
    CHECK(Serialization::serialized_size(vhs) == 17);
  }

  SECTION("pair<Vec, VecHolder>")
  {
    std::pair<Vec, VecHolder> p;
    CHECK(Serialization::serialized_size(p) == 3);
  }
}

TEST_CASE("serialize")
{
  SECTION("Vec")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    auto const serialized = serialize(v);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Serialization::serialized_size(v));
  }

  SECTION("VecHolder")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};

    auto const serialized = serialize(vh);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Serialization::serialized_size(vh));
  }

  SECTION("vector<VecHolder>")
  {
    std::vector<VecHolder> vhs;

    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};

    for (auto i = 0; i < 3; ++i)
      vhs.push_back(vh);

    auto const serialized = serialize(vhs);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Serialization::serialized_size(vhs));
  }

  SECTION("pair<Vec, VecHolder>")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};
    std::pair<Vec, VecHolder> p{v, vh};

    auto const serialized = serialize(p);
    CHECK(serialized.size() == serialized.capacity());
    CHECK(serialized.size() == Serialization::serialized_size(p));
  }
}

TEST_CASE("SerializedSource")
{
  Vec v{{0, 1, 2, 3, 4, 5, 6}};
  auto const serialized = serialize(v);
  SerializedSource ss(serialized);

  SECTION("read")
  {
    auto sp = ss.read(4);
    CHECK(sp.size() == 4);
    // size is the first byte
    CHECK(std::equal(sp.begin() + 1, sp.end(), v.buffer.begin(), v.buffer.begin() + 3));

    sp = ss.read(4);
    CHECK(sp.size() == 4);
    CHECK(std::equal(sp.begin(), sp.end(), v.buffer.begin() + 3, v.buffer.end()));
  }

  SECTION("out of bounds")
  {
    TANKER_CHECK_THROWS_WITH_CODE(ss.read(9), Errc::TruncatedInput);

    CHECK_NOTHROW(ss.read(3));
    TANKER_CHECK_THROWS_WITH_CODE(ss.read(6), Errc::TruncatedInput);

    SerializedSource emptySource;
    TANKER_CHECK_THROWS_WITH_CODE(emptySource.read_varint(), Errc::TruncatedInput);
  }
}

TEST_CASE("deserialize")
{
  Vec v{{0, 1, 2, 3, 4, 5, 6}};
  VecHolder vh{42, v};
  std::vector<VecHolder> vhs{vh, vh, vh, vh};
  std::pair<Vec, VecHolder> p{v, vh};

  auto const serializedVec = serialize(v);
  auto const serializedVecHolder = serialize(vh);
  auto const serializedVecHolders = serialize(vhs);
  auto const serializedPair = serialize(p);

  SECTION("Vec")
  {
    auto const deserializedVec = deserialize<Vec>(serializedVec);
    CHECK(deserializedVec == v);
  }

  SECTION("VecHolder")
  {
    auto const deserializedVecHolder = deserialize<VecHolder>(serializedVecHolder);
    CHECK(deserializedVecHolder == vh);
  }

  SECTION("vector<VecHolder>")
  {
    auto const deserializedVecHolders = deserialize<std::vector<VecHolder>>(serializedVecHolders);
    CHECK(deserializedVecHolders == vhs);
  }

  SECTION("pair<Vec, VecHolder>")
  {
    auto const deserializedPair = deserialize<std::pair<Vec, VecHolder>>(serializedPair);
    CHECK(deserializedPair == p);
  }

  SECTION("should throw if eof not reached")
  {
    TANKER_CHECK_THROWS_WITH_CODE(deserialize<Vec>(serializedVecHolders), Errc::TrailingInput);
  }
}
