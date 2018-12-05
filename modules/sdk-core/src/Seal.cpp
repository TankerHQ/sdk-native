#include <Tanker/Seal.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <numeric>

namespace Tanker
{
namespace
{
auto uniqueSortIndexes(gsl::span<uint64_t const> idxs)
{
  std::vector<uint64_t> indexes(idxs.begin(), idxs.end());

  auto const begin = indexes.begin();
  auto const end = indexes.end();

  std::sort(begin, end);
  auto const last = std::unique(begin, end);
  indexes.erase(last, end);

  return indexes;
}
}

Seal::Range::Range() : first(0), second(0)
{
}

Seal::Range::Range(uint64_t first, uint64_t second)
  : first(first), second(second)
{
  if (first > second)
    throw Error::InvalidArgument("Range error");
}

bool Seal::Range::operator==(Range const& other) const
{
  return first == other.first && second == other.second;
}

Seal::Seal() : _version(Seal::defaultSealVersion())
{
}

Seal::Seal(size_t version,
           std::vector<Range> const& emptyRanges,
           std::vector<Crypto::SymmetricKey> const& keys)
  : _version(version), _emptyRanges(emptyRanges), _keys(keys)
{
}

Seal Seal::inflate(gsl::span<uint8_t const> seal)
{
  if (seal.empty())
    throw Error::DecryptFailed("Empty seal");

  return Serialization::deserialize<Seal>(seal);
}

void Seal::updateRangesAfterRemove(gsl::span<uint64_t const> indexes)
{
  std::size_t offset = 0;
  auto idx = indexes.begin();
  auto const indexesEnd = indexes.end();

  for (auto& range : _emptyRanges)
  {
    if (idx != indexesEnd && *idx <= range.second)
    {
      auto const d = std::min<uint64_t>(std::distance(idx, indexes.end()),
                                        range.second - *idx);
      idx += d;
      offset += d;
    }
    range.first -= offset;
    range.second -= offset;
  }

  mergeAdjacentRanges();
}

void Seal::mergeAdjacentRanges()
{
  if (_emptyRanges.empty())
    return;

  for (auto it = _emptyRanges.begin(), nextIt = std::next(it);
       nextIt != _emptyRanges.end();
       nextIt = std::next(++it))
  {
    if (it->second == nextIt->first || it->second + 1 == nextIt->first)
    {
      it->second = nextIt->second;
      _emptyRanges.erase(nextIt);
    }
  }
}

std::vector<Seal::Range> Seal::splitRange(Range const& range, uint64_t index)
{
  if (range.first > range.second)
    throw Error::InvalidArgument("Range is not ordered");
  // If index is outside of range do nothing
  if (index > range.second || index < range.first)
    return {range};

  if (index == range.first && index == range.second)
    return {};
  else if (index == range.first)
    return {{range.first + 1, range.second}};
  else if (index == range.second)
    return {{range.first, range.second - 1}};
  else
    return {{range.first, index - 1}, {index + 1, range.second}};
}

void Seal::removeFromRanges(gsl::span<uint64_t const> sortedIndexes)
{
  auto indexIt = sortedIndexes.begin();

  for (auto rangeIt = _emptyRanges.begin(); rangeIt != _emptyRanges.end();)
  {
    indexIt =
        std::find_if(indexIt, sortedIndexes.end(), [&](uint64_t const index) {
          return index >= rangeIt->first;
        });
    if (indexIt == sortedIndexes.end())
      break;
    if (*indexIt <= rangeIt->second)
    {
      auto const res = splitRange(*rangeIt, *indexIt);
      rangeIt = _emptyRanges.erase(rangeIt);
      rangeIt = _emptyRanges.insert(rangeIt, res.begin(), res.end());
    }
    else
    {
      rangeIt++;
    }
  }
}

std::size_t Seal::version() const
{
  return _version;
}

std::vector<Crypto::SymmetricKey> const& Seal::keys() const
{
  return _keys;
}

std::vector<Seal::Range> const& Seal::emptyRanges() const
{
  return _emptyRanges;
}

std::size_t Seal::size() const
{
  return serialized_size(*this);
}

void Seal::emplaceRange(Seal::Range range)
{
  if (range.first > range.second)
    throw Error::formatEx<Error::InvalidArgument>(
        "range to emplace is inverted");

  // Extend the last range of the emptyRanges
  if (!_emptyRanges.empty() && _emptyRanges.back().second == range.first - 1)
  {
    _emptyRanges.back().second = range.second;
  }
  else
  {
    _emptyRanges.emplace_back(range.first, range.second);
  }
}

std::vector<uint8_t> Seal::serialize() const
{
  return Serialization::serialize(*this);
}

std::size_t Seal::nbElements() const
{
  size_t indexes =
      std::accumulate(_emptyRanges.begin(),
                      _emptyRanges.end(),
                      0,
                      [](size_t acc, auto const& range) {
                        return acc + range.second + 1 - range.first;
                      });

  return indexes + _keys.size();
}

nonstd::optional<Crypto::SymmetricKey> Seal::chunkAt(size_t index) const
{
  auto const realIndex = convertIndex(index);

  if (realIndex && *realIndex >= _keys.size())
    throw Error::ChunkIndexOutOfRange("Index greater than size of chunks");

  return (realIndex) ?
             nonstd::make_optional<Crypto::SymmetricKey>(_keys[*realIndex]) :
             nonstd::nullopt;
}

nonstd::optional<size_t> Seal::convertIndex(size_t index) const
{
  size_t offset = 0;
  for (auto const& i : _emptyRanges)
  {
    if (index - offset < i.first)
      break;

    if (i.first <= index && i.second >= index)
      return nonstd::nullopt;

    offset += (i.second + 1 - i.first);
  }

  return index - offset;
}

void Seal::remove(gsl::span<uint64_t const> idxs)
{
  if (idxs.size() == 0)
    return;

  auto indexes = uniqueSortIndexes(idxs);

  if (_keys.empty() || indexes.back() > (nbElements() - 1))
  {
    throw Error::formatEx<Error::ChunkIndexOutOfRange>(
        fmt("index '{:d}' is out of range. chunk count : '{:d}'"),
        indexes.back(),
        nbElements());
  }

  for (auto it = indexes.rbegin(); it != indexes.rend(); ++it)
  {
    auto const realIndex = convertIndex(*it);
    if (realIndex)
      _keys.erase(std::next(_keys.begin(), *realIndex));
  }
  removeFromRanges(indexes);
  updateRangesAfterRemove(indexes);
}

void Seal::addChunkAt(Crypto::SymmetricKey chunk, size_t index)
{
  auto const oldsize = nbElements();
  auto const realIndex = convertIndex(index);
  // Append case:
  if (index == oldsize)
  {
    _keys.push_back(chunk);
  }
  // encrypt with holes case:
  else if (index > oldsize)
  {
    emplaceRange({oldsize, index - 1});
    _keys.push_back(chunk);
  }
  // Replace case:
  else
  {
    if (realIndex == nonstd::nullopt)
    {
      std::array<uint64_t, 1> indexes{{index}};
      removeFromRanges(indexes);
      auto const newIndex = convertIndex(index);
      assert(newIndex != nonstd::nullopt && "newIndex should not be null here");
      _keys.insert(std::next(_keys.begin(), *newIndex), chunk);
    }
    else
    {
      _keys[*realIndex] = chunk;
    }
  }
}

std::size_t serialized_size(Seal::Range const& range)
{
  return Serialization::varint_size(range.first) +
         Serialization::varint_size(range.second);
}

void from_serialized(Serialization::SerializedSource& ss, Seal::Range& range)
{
  range.first = ss.read_varint();
  if (ss.eof())
    throw Error::DecryptFailed("truncated seal buffer");
  range.second = ss.read_varint();
  if (range.second < range.first)
    throw Error::DecryptFailed("Empty range is reversed");
}

std::size_t serialized_size(Seal const& seal)
{
  auto const& emptyRanges = seal.emptyRanges();
  auto const& sizeEmptyRanges =
      std::accumulate(emptyRanges.begin(),
                      emptyRanges.end(),
                      Serialization::varint_size(emptyRanges.size() * 2),
                      [](std::size_t acc, auto const& range) {
                        return acc + serialized_size(range);
                      });

  return Serialization::varint_size(seal.version()) + sizeEmptyRanges +
         seal.keys().size() * Crypto::SymmetricKey::arraySize;
}

void from_serialized(Serialization::SerializedSource& ss, Seal& seal)
{
  // Version
  auto const sealVersion = ss.read_varint();
  if (ss.eof())
    throw Error::DecryptFailed("truncated seal buffer");

  std::vector<Seal::Range> sealEmptyRanges;
  auto const sizeEmptyRanges = ss.read_varint();
  if (ss.eof() && sizeEmptyRanges)
    throw Error::DecryptFailed("truncated seal buffer");

  for (std::size_t i = 0; i < sizeEmptyRanges / 2; ++i)
  {
    sealEmptyRanges.push_back(Serialization::deserialize<Seal::Range>(ss));
  }
  // Keys
  std::vector<Crypto::SymmetricKey> sealKeys;
  while (!ss.eof())
  {
    sealKeys.push_back(Serialization::deserialize<Crypto::SymmetricKey>(ss));
  }

  seal = Seal(sealVersion, sealEmptyRanges, sealKeys);
}
}
