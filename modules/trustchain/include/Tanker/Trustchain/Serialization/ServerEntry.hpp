#pragma once

#include <Tanker/Serialization/SerializedSource.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
class ServerEntry;

void from_serialized(Serialization::SerializedSource&, ServerEntry&);
}
}
