#pragma once

#include <Tanker/Crypto/KeyType.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

#include <tuple>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <KeyType Type, KeyUsage Usage>
class AsymmetricKey;
}
}
