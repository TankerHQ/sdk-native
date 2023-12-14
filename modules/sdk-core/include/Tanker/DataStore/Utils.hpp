#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <vector>

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

std::vector<uint8_t> encryptValue(Crypto::SymmetricKey const& userSecret, gsl::span<uint8_t const> value);
tc::cotask<std::vector<uint8_t>> decryptValue(Crypto::SymmetricKey const& userSecret,
                                              gsl::span<uint8_t const> encryptedValue);
}
}
