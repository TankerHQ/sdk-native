#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
Nature DeviceCreation::nature() const
{
  return boost::variant2::visit([](auto const& a) { return a.nature(); },
                                _variant);
}

bool DeviceCreation::isGhostDevice() const
{
  if (auto dc3 = boost::variant2::get_if<DeviceCreation3>(&_variant))
    return dc3->isGhostDevice();
  return false;
}

std::vector<std::uint8_t> DeviceCreation::signatureData() const
{
  return boost::variant2::visit(
      [&](auto const& val) { return val.signatureData(); }, _variant);
}

Crypto::Signature const& DeviceCreation::sign(
    Crypto::PrivateSignatureKey const& key)
{
  return boost::variant2::visit(
      [&](auto& val) -> decltype(auto) { return val.sign(key); }, _variant);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceCreation const& dc)
{
  return Serialization::serialize(it, dc._variant);
}

std::size_t serialized_size(DeviceCreation const& dc)
{
  return Serialization::serialized_size(dc._variant);
}

void to_json(nlohmann::json& j, DeviceCreation const& dc)
{
  boost::variant2::visit([&j](auto const& val) { j = val; }, dc._variant);
}
}
}
}
