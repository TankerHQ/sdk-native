#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tuple>
#include <vector>

namespace Tanker::ResourceKeys
{
using KeysResult =
    std::vector<std::tuple<Crypto::SymmetricKey, Trustchain::ResourceId>>;
}
