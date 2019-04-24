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
class UserGroupAddition;

void from_serialized(Serialization::SerializedSource&, UserGroupAddition&);

std::uint8_t* to_serialized(std::uint8_t*, UserGroupAddition const&);

std::size_t serialized_size(UserGroupAddition const&);
}
}
}

