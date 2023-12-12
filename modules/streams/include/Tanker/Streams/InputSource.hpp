#pragma once

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <functional>

namespace Tanker
{
namespace Streams
{
// Callback type used in EncryptionStream/DecryptionStream to retrieve input in
// out. It must read at most n bytes, and returns the number of bytes read,
// or 0 when EOF is reached.
//
// Throws if an error occurred.
using InputSource = std::function<tc::cotask<std::int64_t>(gsl::span<std::uint8_t> out)>;
}
}
