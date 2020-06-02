#include <Tanker/Trustchain/KeyPublishAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker::Trustchain
{
Crypto::Hash getHash(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.hash(); },
                                action);
}

Actions::Nature getNature(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.nature(); },
                                action);
}

Crypto::Hash const& getAuthor(KeyPublishAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.author(); }, action);
}

Crypto::Signature const& getSignature(KeyPublishAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.signature(); },
      action);
}

KeyPublishAction deserializeKeyPublishAction(
    gsl::span<std::uint8_t const> block)
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
  case Nature::KeyPublishToUser:
    return Serialization::deserialize<KeyPublishToUser>(block);
  case Nature::KeyPublishToUserGroup:
    return Serialization::deserialize<KeyPublishToUserGroup>(block);
  case Nature::KeyPublishToProvisionalUser:
    return Serialization::deserialize<KeyPublishToProvisionalUser>(block);
  default:
    // remove the static_cast and this line will make fmt dereference a null
    // pointer, deep in its internals
    throw Errors::AssertionError(fmt::format(
        TFMT("{} is not a key publish block"), static_cast<int>(nature)));
  }
}
}
