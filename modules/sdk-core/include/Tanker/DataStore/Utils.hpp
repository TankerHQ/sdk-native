#pragma once

#include <cstdint>

#include <gsl-lite.hpp>

namespace Tanker
{
namespace DataStore
{
template <typename T = gsl::span<uint8_t const>, typename Field = void>
T extractBlob(Field const& f)
{
  return T(f.blob, f.blob + f.len);
}
}
}
