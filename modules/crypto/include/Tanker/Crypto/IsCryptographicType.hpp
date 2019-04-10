#pragma once

#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <typename T, typename = void>
struct IsCryptographicType : std::false_type
{
};
}
}
