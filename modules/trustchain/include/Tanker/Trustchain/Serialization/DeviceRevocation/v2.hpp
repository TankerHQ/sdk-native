#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation2;

void from_serialized(Serialization::SerializedSource&, DeviceRevocation2&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation2 const&);

std::size_t serialized_size(DeviceRevocation2 const&);
}
}
}
