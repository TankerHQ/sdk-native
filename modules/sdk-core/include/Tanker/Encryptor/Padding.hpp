#pragma once

#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <vector>

namespace Tanker::Padding
{
constexpr uint64_t minimalPadding()
{
  return 10;
}
uint64_t padme(uint64_t clearSize);
uint64_t paddedFromClearSize(uint64_t clearSize);
std::vector<uint8_t> padClearData(gsl::span<uint8_t const> clearData);
uint64_t unpaddedSize(gsl::span<uint8_t const> paddedData);
}
