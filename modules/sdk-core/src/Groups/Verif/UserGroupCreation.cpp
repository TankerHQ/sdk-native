#include <Tanker/Groups/Verif/UserGroupCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
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
Trustchain::GroupAction verifyUserGroupCreation(Trustchain::GroupAction const& action,
                                                Users::Device const& author,
                                                std::optional<BaseGroup> const& previousGroup)
{
  assert(getNature(action) == Nature::UserGroupCreation1 || getNature(action) == Nature::UserGroupCreation2 ||
         getNature(action) == Nature::UserGroupCreation3);

  ensures(!previousGroup, Verif::Errc::InvalidGroup, "UserGroupCreation - group already exist");

  ensures(Crypto::verify(getHash(action), getSignature(action), author.publicSignatureKey()),
          Errc::InvalidSignature,
          "UserGroupCreation block must be signed by the author device");

  auto const& userGroupCreation = boost::variant2::get<UserGroupCreation>(action);

  ensures(
      Crypto::verify(
          userGroupCreation.signatureData(), userGroupCreation.selfSignature(), userGroupCreation.publicSignatureKey()),
      Errc::InvalidSignature,
      "UserGroupCreation signature data must be signed with the group "
      "public key");

  return action;
}
}
}
