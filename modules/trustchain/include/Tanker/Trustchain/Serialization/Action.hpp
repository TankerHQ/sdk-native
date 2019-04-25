#pragma once

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
class Action;
// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for Action.
std::uint8_t* to_serialized(std::uint8_t*, Action const&);

std::size_t serialized_size(Action const&);
}
}
