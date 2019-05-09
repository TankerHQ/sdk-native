#include <Tanker/Trustchain/Actions/KeyPublish.hpp>

#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
Nature KeyPublish::nature() const
{
  return visit([](auto const& val) { return val.nature(); });
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublish const& kp)
{
  return kp.visit(
      [it](auto const& val) { return Serialization::serialize(it, val); });
}

std::size_t serialized_size(KeyPublish const& kp)
{
  return kp.visit(
      [](auto const& val) { return Serialization::serialized_size(val); });
}

void to_json(nlohmann::json& j, KeyPublish const& kp)
{
  return kp.visit([&j](auto const& val) { j = val; });
}
}
}
}
