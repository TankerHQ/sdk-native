#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation1;

void from_serialized(Serialization::SerializedSource&, DeviceRevocation1&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation1 const&);

constexpr std::size_t serialized_size(DeviceRevocation1 const&)
{
  return DeviceId::arraySize;
}
}
}
}
