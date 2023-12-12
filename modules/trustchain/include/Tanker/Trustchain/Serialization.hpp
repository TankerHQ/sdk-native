#pragma once

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

namespace Tanker::Trustchain
{
Actions::Nature getBlockNature(gsl::span<std::uint8_t const> block);
void deserializeBlockVersion(Serialization::SerializedSource& ss);
void deserializeBlockNature(Serialization::SerializedSource& ss, Actions::Nature expected);
}
