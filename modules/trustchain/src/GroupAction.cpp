#include <Tanker/Trustchain/GroupAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker::Trustchain
{
Crypto::Hash getHash(GroupAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) {
        return val.visit([&](auto const& val) { return val.hash(); });
      },
      action);
}

Actions::Nature getNature(GroupAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.nature(); },
                                action);
}

Crypto::Hash const& getAuthor(GroupAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.author(); }, action);
}

Crypto::Signature const& getSignature(GroupAction const& action)
{
  return boost::variant2::visit(
      [&](auto const& val) -> decltype(auto) { return val.signature(); },
      action);
}

GroupAction deserializeGroupAction(gsl::span<std::uint8_t const> block)
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
  case Nature::UserGroupCreation1:
    return Serialization::deserialize<UserGroupCreation1>(block);
  case Nature::UserGroupCreation2:
    return Serialization::deserialize<UserGroupCreation2>(block);
  case Nature::UserGroupAddition1:
    return Serialization::deserialize<UserGroupAddition1>(block);
  case Nature::UserGroupAddition2:
    return Serialization::deserialize<UserGroupAddition2>(block);
  default:
    // remove the static_cast and this line will make fmt dereference a null
    // pointer, deep in its internals
    throw Errors::AssertionError(
        fmt::format(TFMT("{} is not a group block"), static_cast<int>(nature)));
  }
}
}
