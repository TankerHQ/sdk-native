#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <gsl-lite.hpp>
#include <optional.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{

class Seal
{
public:
  struct Range
  {
    uint64_t first;
    uint64_t second;

    Range();
    Range(uint64_t first, uint64_t second);
    bool operator==(Range const& other) const;
  };

public:
  // This should be a variable but it fails to link in cpp < 17 because
  // constexpr static members have external linkage ...
  constexpr static uint32_t defaultSealVersion()
  {
    return 3u;
  }

public:
  static Seal inflate(gsl::span<uint8_t const> seal);

public:
  Seal();
  std::vector<uint8_t> serialize() const;
  void removeFromRanges(gsl::span<uint64_t const> sortedIndexes);
  void emplaceRange(Range range);

  std::size_t nbElements() const;
  nonstd::optional<Crypto::SymmetricKey> chunkAt(size_t index) const;
  void remove(gsl::span<uint64_t const> idxs);
  void addChunkAt(Crypto::SymmetricKey chunk, size_t index);

  // Getters
  std::size_t version() const;
  std::vector<Crypto::SymmetricKey> const& keys() const;
  std::vector<Range> const& emptyRanges() const;
  std::size_t size() const;

public:
  // Internal functions only public for tests purposes
  std::vector<Range> splitRange(Range const& range, uint64_t index);
  void updateRangesAfterRemove(gsl::span<uint64_t const> indexes);

private:
  Seal(size_t version,
       std::vector<Range> const& emptyRanges,
       std::vector<Crypto::SymmetricKey> const& keys);

private:
  nonstd::optional<size_t> convertIndex(size_t index) const;
  void mergeAdjacentRanges();
  friend void from_serialized(Serialization::SerializedSource&, Seal&);

private:
  size_t _version{3u};
  std::vector<Range> _emptyRanges;
  std::vector<Crypto::SymmetricKey> _keys;
};

std::size_t serialized_size(Seal::Range const& range);
void from_serialized(Serialization::SerializedSource& ss, Seal::Range& range);
std::size_t serialized_size(Seal const& seal);
void from_serialized(Serialization::SerializedSource& ss, Seal& seal);

template <typename OutputIterator>
void to_serialized(OutputIterator it, Seal::Range const& range)
{
  Serialization::varint_write(*it, range.first);
  Serialization::varint_write(*it, range.second);
}

template <typename OutputIterator>
void to_serialized(OutputIterator it, Seal const& seal)
{
  Serialization::varint_write(it, Seal::defaultSealVersion());
  auto const& emptyRanges = seal.emptyRanges();
  Serialization::varint_write(it, emptyRanges.size() * 2);
  for (auto const& elt : emptyRanges)
  {
    Serialization::serialize(it, elt);
  }
  for (auto const& key : seal.keys())
  {
    Serialization::serialize(it, key);
  }
}
}
