#include <Tanker/Groups/Verif/UserGroupUpdate.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/UserGroupUpdate.hpp>
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
Trustchain::GroupAction verifyUserGroupUpdate(
    Trustchain::GroupAction const& action,
    Users::Device const& author,
    std::optional<BaseGroup> const& group)
{
  assert(getNature(action) == Nature::UserGroupUpdate1);

  ensures(group.has_value(),
          Verif::Errc::InvalidGroup,
          "UserGroupUpdate references unknown group");

  ensures(
      Crypto::verify(
          getHash(action), getSignature(action), author.publicSignatureKey()),
      Errc::InvalidSignature,
      "UserGroupUpdate block must be signed by the author device");

  auto const& userGroupUpdate = boost::variant2::get<UserGroupUpdate>(action);

  ensures(userGroupUpdate.previousKeyRotationBlockHash() == group->lastKeyRotationBlockHash(),
          Errc::InvalidGroup,
          "UserGroupUpdate - previous key rotation block does not match for this "
          "group id");

  ensures(Crypto::verify(userGroupUpdate.signatureData(),
                         userGroupUpdate.selfSignatureWithCurrentKey(),
                         userGroupUpdate.publicSignatureKey()),
          Errc::InvalidSignature,
          "UserGroupUpdate signature data must be signed with the new group "
          "public key");

  ensures(
      Crypto::verify(userGroupUpdate.signatureData(),
                     userGroupUpdate.selfSignatureWithPreviousKey(),
                     group->publicSignatureKey()),
      Errc::InvalidSignature,
      "UserGroupUpdate signature data must be signed with the previous group "
      "public key");

  return action;
}
}
}
