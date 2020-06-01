#include <Tanker/Trustchain/UserAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker::Trustchain
{
Crypto::Hash getHash(UserAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) {
        return val.visit([&](auto const& val) { return val.hash(); });
      },
      action);
}

Actions::Nature getNature(UserAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.nature(); },
                                action);
}

Crypto::Hash const& getAuthor(UserAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.author(); }, action);
}

Crypto::Signature const& getSignature(UserAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.signature(); },
      action);
}

UserAction deserializeUserAction(gsl::span<std::uint8_t const> block)
{
  if (block.size() < 2)
    throw Errors::formatEx(Errc::InvalidBlockVersion, "block too small");
  if (block[0] != 1)
    throw Errors::formatEx(
        Errc::InvalidBlockVersion, "unsupported block version: {}", block[0]);

  auto rest = Serialization::varint_read(block.subspan(1)).second;
  auto const nature = static_cast<Nature>(rest[32]);

  switch (nature)
  {
  case Nature::DeviceCreation:
    return Serialization::deserialize<DeviceCreation1>(block);
  case Nature::DeviceCreation2:
    return Serialization::deserialize<DeviceCreation2>(block)
        .asDeviceCreation1();
  case Nature::DeviceCreation3:
    return Serialization::deserialize<DeviceCreation3>(block);
  case Nature::DeviceRevocation:
    return Serialization::deserialize<DeviceRevocation1>(block);
  case Nature::DeviceRevocation2:
    return Serialization::deserialize<DeviceRevocation2>(block);
  default:
    // remove the static_cast and this line will make fmt dereference a null
    // pointer, deep in its internals
    throw Errors::AssertionError(
        fmt::format(TFMT("{} is not a group block"), static_cast<int>(nature)));
  }
}
}
