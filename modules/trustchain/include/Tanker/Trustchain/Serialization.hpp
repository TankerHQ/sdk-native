#pragma once

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

namespace Tanker::Trustchain
{
void deserializeBlockVersion(Serialization::SerializedSource& ss);
void deserializeBlockNature(Serialization::SerializedSource& ss,
                            Actions::Nature expected);
}
