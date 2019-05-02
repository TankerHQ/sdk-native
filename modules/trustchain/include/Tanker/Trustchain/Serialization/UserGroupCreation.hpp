#pragma once

#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for UserGroupCreation.
std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation const&);

std::size_t serialized_size(UserGroupCreation const&);
}
}
}
