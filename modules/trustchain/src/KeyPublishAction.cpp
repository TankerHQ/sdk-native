#include <Tanker/Trustchain/KeyPublishAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker::Trustchain
{
Crypto::Hash getHash(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.hash(); }, action);
}

Actions::Nature getNature(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.nature(); }, action);
}

Crypto::Hash const& getAuthor(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) -> decltype(auto) { return val.author(); }, action);
}

Crypto::Signature const& getSignature(KeyPublishAction const& action)
{
  return boost::variant2::visit([&](auto const& val) -> decltype(auto) { return val.signature(); }, action);
}

KeyPublishAction deserializeKeyPublishAction(gsl::span<std::uint8_t const> block)
{
  auto const nature = getBlockNature(block);

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
    throw Errors::formatEx(Errors::Errc::UpgradeRequired,
                           "{} is not a known key publish block nature, Tanker "
                           "needs to be updated",
                           static_cast<int>(nature));
  }
}
}
