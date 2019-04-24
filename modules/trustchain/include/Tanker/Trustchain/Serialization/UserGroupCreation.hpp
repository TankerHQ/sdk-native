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
class UserGroupCreation;

void from_serialized(Serialization::SerializedSource&, UserGroupCreation&);

std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation const&);

std::size_t serialized_size(UserGroupCreation const&);
}
}
}

