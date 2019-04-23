#pragma once

#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for DeviceRevocation.
// from_serialized(Action&) will construct abstract actions.
std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);

std::size_t serialized_size(DeviceRevocation const&);
}
}
}
