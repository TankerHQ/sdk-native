#include <Tanker/Crypto/Padding.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <cmath>

namespace Tanker::Padding
{
namespace
{
uint64_t computeNextMultiple(uint64_t multipleOf, uint64_t biggerThan)
{
  auto remainder = biggerThan % multipleOf;
  if (remainder == 0)
    return biggerThan;
  return biggerThan + multipleOf - remainder;
}
}

uint64_t padme(uint64_t clearSize)
{
  if (clearSize <= 1)
    return 0;

  auto const e = static_cast<uint64_t>(std::floor(std::log2(clearSize)));
  auto const s = static_cast<uint64_t>(std::floor(std::log2(e)) + 1ULL);
  auto const lastBits = e - s;
  auto const bitMask = (1ULL << lastBits) - 1ULL;
  return (clearSize + bitMask) & ~bitMask;
}

uint64_t paddedFromClearSize(uint64_t clearSize, std::optional<uint32_t> paddingStep)
{
  if (!paddingStep)
    return std::max(padme(clearSize), minimalPadding()) + 1;

  if (*paddingStep < 1)
    throw Errors::AssertionError("paddingStep should be greater or equal to 1");

  // Round 0 up to paddingStep (plus the padding byte)
  if (clearSize == 0)
    return *paddingStep + 1;

  return computeNextMultiple(*paddingStep, clearSize) + 1;
}

std::vector<uint8_t> padClearData(gsl::span<uint8_t const> clearData, std::optional<uint32_t> paddingStep)
{
  auto const paddedSize = paddedFromClearSize(clearData.size(), paddingStep);
  if (paddedSize < clearData.size() + 1)
    throw Errors::AssertionError("paddedSize is too small");

  std::vector<std::uint8_t> res;
  res.reserve(paddedSize);
  res.insert(res.begin(), clearData.begin(), clearData.end());
  res.push_back(0x80);
  res.resize(paddedSize, 0x00);

  return res;
}

uint64_t unpaddedSize(gsl::span<const uint8_t> paddedData)
{
  auto const it = std::find_if(paddedData.crbegin(), paddedData.crend(), [](auto const& c) { return c != 0x00; });

  if (it == paddedData.crend() || *it != 0x80)
    throw Errors::formatEx(Errors::Errc::DecryptionFailed, "unable to remove padding");

  return std::distance(it + 1, paddedData.crend());
}
}
