#pragma once

#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <functional>

namespace Tanker
{
// Callback type used in StreamEncryptor/StreamDecryptor to retrieve input in
// out. It must read at most n bytes, and returns the number of bytes read,
// or 0 when EOF is reached.
//
// Throws if an error occurred.
using StreamInputSource =
    std::function<tc::cotask<std::int64_t>(std::uint8_t* out, std::int64_t n)>;
}
