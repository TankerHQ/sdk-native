#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
Nature UserGroupCreation::nature() const
{
  return boost::variant2::visit([](auto const& a) { return a.nature(); },
                                _variant);
}

std::vector<std::uint8_t> UserGroupCreation::signatureData() const
{
  return boost::variant2::visit(
      [&](auto const& val) { return val.signatureData(); }, _variant);
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(UserGroupCreation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}

void to_json(nlohmann::json& j, UserGroupCreation const& dc)
{
  boost::variant2::visit([&j](auto const& val) { j = val; }, dc._variant);
}
}
}
}
