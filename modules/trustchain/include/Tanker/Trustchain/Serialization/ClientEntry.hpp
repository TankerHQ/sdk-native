#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>

#include <cstdint>
#include <cstddef>

namespace Tanker
{
namespace Trustchain
{
class ClientEntry;

std::uint8_t* to_serialized(std::uint8_t*, ClientEntry const&);

std::size_t serialized_size(ClientEntry const&);
}
}
