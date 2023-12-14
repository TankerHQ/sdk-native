#include <Tanker/Trustchain/GroupAction.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;

namespace Tanker::Trustchain
{
Crypto::Hash getHash(GroupAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.visit([&](auto const& val) { return val.hash(); }); },
                                action);
}

Actions::Nature getNature(GroupAction const& action)
{
  return boost::variant2::visit([&](auto const& val) { return val.nature(); }, action);
}

Crypto::Hash const& getAuthor(GroupAction const& action)
{
  return boost::variant2::visit([&](auto const& val) -> decltype(auto) { return val.author(); }, action);
}

Crypto::Signature const& getSignature(GroupAction const& action)
{
  return boost::variant2::visit([&](auto const& val) -> decltype(auto) { return val.signature(); }, action);
}

GroupId getGroupId(GroupAction const& action)
{
  using namespace boost::variant2;

  if (auto ugc = get_if<Actions::UserGroupCreation>(&action))
    return GroupId{ugc->publicSignatureKey()};
  else if (auto uga = get_if<Actions::UserGroupAddition>(&action))
    return uga->groupId();
  throw Errors::AssertionError{"getGroupId: unexpected type in variant"};
}

GroupAction deserializeGroupAction(gsl::span<std::uint8_t const> block)
{
  auto const nature = getBlockNature(block);

  switch (nature)
  {
  case Nature::UserGroupCreation1:
    return Serialization::deserialize<UserGroupCreation1>(block);
  case Nature::UserGroupCreation2:
    return Serialization::deserialize<UserGroupCreation2>(block);
  case Nature::UserGroupCreation3:
    return Serialization::deserialize<UserGroupCreation3>(block);
  case Nature::UserGroupAddition1:
    return Serialization::deserialize<UserGroupAddition1>(block);
  case Nature::UserGroupAddition2:
    return Serialization::deserialize<UserGroupAddition2>(block);
  case Nature::UserGroupAddition3:
    return Serialization::deserialize<UserGroupAddition3>(block);
  default:
    // remove the static_cast and this line will make fmt dereference a null
    // pointer, deep in its internals
    throw Errors::formatEx(Errors::Errc::UpgradeRequired,
                           "{} is not a known group block nature, Tanker needs to be updated",
                           static_cast<int>(nature));
  }
}
}
