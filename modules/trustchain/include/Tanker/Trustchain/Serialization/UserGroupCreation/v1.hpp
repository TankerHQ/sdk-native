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
class UserGroupCreation1;

void from_serialized(Serialization::SerializedSource&, UserGroupCreation1&);

std::uint8_t* to_serialized(std::uint8_t*, UserGroupCreation1 const&);

std::size_t serialized_size(UserGroupCreation1 const&);
}
}
}

