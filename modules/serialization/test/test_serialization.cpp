#include <Tanker/Serialization/Serialization.hpp>

#include <doctest.h>
#include <gsl-lite.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>

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
  return Tanker::Serialization::serialized_size(vh.vec) + sizeof(vh.byte);
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
  return Tanker::Serialization::serialize(it, vh.vec);
}

void from_serialized(Tanker::Serialization::SerializedSource& ss, Vec& v)
{
  auto const size = ss.read(1)[0];
  auto const sp = ss.read(size);
  v.buffer.reserve(sp.size());
  std::copy(sp.begin(), sp.end(), std::back_inserter(v.buffer));
}

void from_serialized(Tanker::Serialization::SerializedSource& ss, VecHolder& vh)
{
  vh.byte = ss.read(1)[0];
  vh.vec = Tanker::Serialization::deserialize<Vec>(ss);
}
}

TEST_CASE("serialized_size")
{
  SUBCASE("Vec")
  {
    Vec v;
    CHECK(Tanker::Serialization::serialized_size(v) == 1);

    v.buffer.resize(10);
    CHECK(Tanker::Serialization::serialized_size(v) == 11);
  }

  SUBCASE("VecHolder")
  {
    VecHolder vh;
    CHECK(Tanker::Serialization::serialized_size(vh) == 2);

    vh.vec.buffer.resize(10);
    CHECK(Tanker::Serialization::serialized_size(vh) == 12);
  }

  SUBCASE("vector<VecHolder>")
  {
    std::vector<VecHolder> vhs(3);
    CHECK(Tanker::Serialization::serialized_size(vhs) ==
          1 + 3 * Tanker::Serialization::serialized_size(vhs.front()));

    vhs.front().vec.buffer.resize(10);
    CHECK(Tanker::Serialization::serialized_size(vhs) == 17);
  }

  SUBCASE("pair<Vec, VecHolder>")
  {
    std::pair<Vec, VecHolder> p;
    CHECK(Tanker::Serialization::serialized_size(p) == 3);
  }
}

TEST_CASE("serialize")
{
  SUBCASE("Vec")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    auto const serialized = Tanker::Serialization::serialize(v);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Tanker::Serialization::serialized_size(v));
  }

  SUBCASE("VecHolder")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};

    auto const serialized = Tanker::Serialization::serialize(vh);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Tanker::Serialization::serialized_size(vh));
  }

  SUBCASE("vector<VecHolder>")
  {
    std::vector<VecHolder> vhs;

    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};

    for (auto i = 0; i < 3; ++i)
      vhs.push_back(vh);

    auto const serialized = Tanker::Serialization::serialize(vhs);

    CHECK(serialized.capacity() == serialized.size());
    CHECK(serialized.size() == Tanker::Serialization::serialized_size(vhs));
  }

  SUBCASE("pair<Vec, VecHolder>")
  {
    Vec v{{0, 1, 2, 3, 4, 5, 6}};
    VecHolder vh{42, v};
    std::pair<Vec, VecHolder> p{v, vh};

    auto const serialized = Tanker::Serialization::serialize(p);
    CHECK(serialized.size() == serialized.capacity());
    CHECK(serialized.size() == Tanker::Serialization::serialized_size(p));
  }
}

TEST_CASE("SerializedSource")
{
  Vec v{{0, 1, 2, 3, 4, 5, 6}};
  auto const serialized = Tanker::Serialization::serialize(v);
  Tanker::Serialization::SerializedSource ss(serialized);

  SUBCASE("read")
  {
    auto sp = ss.read(4);
    CHECK(sp.size() == 4);
    // size is the first byte
    CHECK(std::equal(
        sp.begin() + 1, sp.end(), v.buffer.begin(), v.buffer.begin() + 3));

    sp = ss.read(4);
    CHECK(sp.size() == 4);
    CHECK(
        std::equal(sp.begin(), sp.end(), v.buffer.begin() + 3, v.buffer.end()));
  }

  SUBCASE("out of bounds")
  {
    CHECK_THROWS(ss.read(9));

    CHECK_NOTHROW(ss.read(3));
    CHECK_THROWS(ss.read(6));

    Tanker::Serialization::SerializedSource emptySource;
    CHECK_THROWS(emptySource.read_varint());
  }
}

TEST_CASE("deserialize")
{
  Vec v{{0, 1, 2, 3, 4, 5, 6}};
  VecHolder vh{42, v};
  std::vector<VecHolder> vhs{vh, vh, vh, vh};
  std::pair<Vec, VecHolder> p{v, vh};

  auto const serializedVec = Tanker::Serialization::serialize(v);
  auto const serializedVecHolder = Tanker::Serialization::serialize(vh);
  auto const serializedVecHolders = Tanker::Serialization::serialize(vhs);
  auto const serializedPair = Tanker::Serialization::serialize(p);

  SUBCASE("Vec")
  {
    auto const deserializedVec =
        Tanker::Serialization::deserialize<Vec>(serializedVec);
    CHECK(deserializedVec == v);
  }

  SUBCASE("VecHolder")
  {
    auto const deserializedVecHolder =
        Tanker::Serialization::deserialize<VecHolder>(serializedVecHolder);
    CHECK(deserializedVecHolder == vh);
  }

  SUBCASE("vector<VecHolder>")
  {
    auto const deserializedVecHolders =
        Tanker::Serialization::deserialize<std::vector<VecHolder>>(
            serializedVecHolders);
    CHECK(deserializedVecHolders == vhs);
  }

  SUBCASE("pair<Vec, VecHolder>")
  {
    auto const deserializedPair =
        Tanker::Serialization::deserialize<std::pair<Vec, VecHolder>>(
            serializedPair);
    CHECK(deserializedPair == p);
  }

  SUBCASE("should throw if eof not reached")
  {
    CHECK_THROWS(Tanker::Serialization::deserialize<Vec>(serializedVecHolders));
  }
}
