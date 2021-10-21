#include <Tanker/Encryptor/Padding.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <cmath>

namespace Tanker
{
namespace
{
uint64_t computeNextMultiple(uint64_t multipleOf, uint64_t biggerThan)
{
  return multipleOf * ((biggerThan + multipleOf - 1) / multipleOf);
}
}

uint64_t Padding::padme(uint64_t clearSize)
{
  if (clearSize <= 1)
    return 0;

  auto const e = static_cast<uint64_t>(std::floor(std::log2(clearSize)));
  auto const s = static_cast<uint64_t>(std::floor(std::log2(e)) + 1ULL);
  auto const lastBits = e - s;
  auto const bitMask = (1ULL << lastBits) - 1ULL;
  return (clearSize + bitMask) & ~bitMask;
}

uint64_t Padding::paddedFromClearSize(uint64_t clearSize,
                                      std::optional<uint32_t> paddingStep)
{
  auto const minimalPaddedSize = clearSize + 1;

  if (!paddingStep)
    return std::max(padme(minimalPaddedSize), minimalPadding());

  if (*paddingStep == Auto || *paddingStep == Off)
    throw Errors::AssertionError("paddingStep should be greater than 1");

  return computeNextMultiple(*paddingStep, minimalPaddedSize);
}

std::vector<uint8_t> Padding::padClearData(gsl::span<uint8_t const> clearData,
                                           std::optional<uint32_t> paddingStep)
{
  std::vector<std::uint8_t> res(clearData.begin(), clearData.end());
  res.push_back(0x80);

  auto const paddedSize = paddedFromClearSize(clearData.size(), paddingStep);
  res.resize(paddedSize, 0x00);

  return res;
}

uint64_t Padding::unpaddedSize(gsl::span<const uint8_t> paddedData)
{
  auto const it = std::find_if(paddedData.crbegin(),
                               paddedData.crend(),
                               [](auto const& c) { return c != 0x00; });

  if (it == paddedData.crend() || *it != 0x80)
    throw Errors::formatEx(Errors::Errc::DecryptionFailed,
                           "unable to remove padding");

  return std::distance(it + 1, paddedData.crend());
}
}
