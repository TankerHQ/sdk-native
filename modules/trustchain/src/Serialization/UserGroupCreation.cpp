#include <Tanker/Trustchain/Serialization/UserGroupCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(UserGroupCreation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}
}
}
}
