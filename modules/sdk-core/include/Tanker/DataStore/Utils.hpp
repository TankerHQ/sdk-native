#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <cstdint>

#include <gsl/gsl-lite.hpp>

namespace Tanker
{
namespace DataStore
{
template <typename T = gsl::span<uint8_t const>, typename Field = void>
T extractBlob(Field const& f)
{
  return T(f.blob, f.blob + f.len);
}

[[noreturn]] void handleError(Errors::Exception const& e);
}
}
