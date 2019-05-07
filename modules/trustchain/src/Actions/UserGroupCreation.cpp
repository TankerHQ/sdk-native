#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

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
  return mpark::visit([](auto const& a) { return a.nature(); }, _variant);
}

std::vector<std::uint8_t> UserGroupCreation::signatureData() const
{
  return mpark::visit([&](auto const& val) { return val.signatureData(); },
                      _variant);
}

Crypto::Signature const& UserGroupCreation::selfSign(
    Crypto::PrivateSignatureKey const& key)
{
  return mpark::visit(
      [&](auto& val) -> decltype(auto) { return val.selfSign(key); }, _variant);
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
  mpark::visit([&j](auto const& val) { j = val; }, dc._variant);
}
}
}
}
