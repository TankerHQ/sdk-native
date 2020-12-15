#include <Tanker/Trustchain/UserAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

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
  auto const nature = getBlockNature(block);

  switch (nature)
  {
  case Nature::DeviceCreation1:
    return Serialization::deserialize<DeviceCreation1>(block);
  case Nature::DeviceCreation2:
    return Serialization::deserialize<DeviceCreation2>(block)
        .asDeviceCreation1();
  case Nature::DeviceCreation3:
    return Serialization::deserialize<DeviceCreation3>(block);
  case Nature::DeviceRevocation1:
    return Serialization::deserialize<DeviceRevocation1>(block);
  case Nature::DeviceRevocation2:
    return Serialization::deserialize<DeviceRevocation2>(block);
  default:
    // remove the static_cast and this line will make fmt dereference a null
    // pointer, deep in its internals
    throw Errors::formatEx(
        Errors::Errc::UpgradeRequired,
        "{} is not a known user block nature, Tanker needs to be updated",
        static_cast<int>(nature));
  }
}
}
