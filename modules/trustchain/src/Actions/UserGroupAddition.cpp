#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
Nature UserGroupAddition::nature() const
{
  return visit([](auto const& val) { return val.nature(); });
}

std::vector<std::uint8_t> UserGroupAddition::signatureData() const
{
  return visit([](auto const& val) { return val.signatureData(); });
}

Crypto::Signature const& UserGroupAddition::selfSign(
    Crypto::PrivateSignatureKey const& key)
{
  return mpark::visit(
      [&](auto& val) -> decltype(auto) { return val.selfSign(key); }, _variant);
}

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupAddition const& uga)
{
  return uga.visit(
      [it](auto const& val) { return Serialization::to_serialized(it, val); });
}

std::size_t serialized_size(UserGroupAddition const& uga)
{
  return uga.visit(
      [](auto const& val) { return Serialization::serialized_size(val); });
}

void to_json(nlohmann::json& j, UserGroupAddition const& uga)
{
  return uga.visit([&j](auto const& val) { j = val; });
}
}
}
}
