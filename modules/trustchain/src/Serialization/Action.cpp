#include <Tanker/Trustchain/Action.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
std::uint8_t* to_serialized(std::uint8_t* it, Action const& a)
{
  return a.visit(
      [it](auto const& val) { return Serialization::serialize(it, val); });
}

std::size_t serialized_size(Action const& a)
{
  return a.visit(
      [](auto const& val) { return Serialization::serialized_size(val); });
}
}
}
