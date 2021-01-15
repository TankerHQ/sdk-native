#include <Tanker/Groups/Verif/UserGroupAddition.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
Trustchain::GroupAction verifyUserGroupAddition(
    Trustchain::GroupAction const& action,
    Users::Device const& author,
    std::optional<BaseGroup> const& group)
{
  assert(getNature(action) == Nature::UserGroupAddition1 ||
         getNature(action) == Nature::UserGroupAddition2 ||
         getNature(action) == Nature::UserGroupAddition3);

  ensures(group.has_value(),
          Verif::Errc::InvalidGroup,
          "UserGroupAddition references unknown group");

  ensures(
      Crypto::verify(
          getHash(action), getSignature(action), author.publicSignatureKey()),
      Errc::InvalidSignature,
      "UserGroupAddition block must be signed by the author device");

  auto const& userGroupAddition =
      boost::variant2::get<UserGroupAddition>(action);

  ensures(userGroupAddition.previousGroupBlockHash() == group->lastBlockHash(),
          Errc::InvalidGroup,
          "UserGroupAddition - previous group block does not match for this "
          "group id");

  ensures(Crypto::verify(userGroupAddition.signatureData(),
                         userGroupAddition.selfSignature(),
                         group->publicSignatureKey()),
          Errc::InvalidSignature,
          "UserGroupAddition signature data must be signed with the group "
          "public key");

  return action;
}
}
}
