#pragma once

#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <optional>
#include <vector>

namespace Tanker::Padding
{
inline constexpr auto Auto = 0;
inline constexpr auto Off = 1;

constexpr uint64_t minimalPadding()
{
  return 10;
}
uint64_t padme(uint64_t clearSize);
uint64_t paddedFromClearSize(uint64_t clearSize,
                             std::optional<uint32_t> paddingStep);
std::vector<uint8_t> padClearData(gsl::span<uint8_t const> clearData,
                                  std::optional<uint32_t> paddingStep);
uint64_t unpaddedSize(gsl::span<uint8_t const> paddedData);
}
