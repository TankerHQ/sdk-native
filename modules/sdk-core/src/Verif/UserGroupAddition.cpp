#include <Tanker/Verif/UserGroupAddition.hpp>

#include <Tanker/Actions/UserGroupAddition.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

namespace Tanker
{
namespace Verif
{
void verifyUserGroupAddition(UnverifiedEntry const& entry,
                             Device const& author,
                             ExternalGroup const& group)
{
  assert(entry.nature == Nature::UserGroupAddition);

  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "UserGroupAddition block must be signed by the author device");

  auto const& userGroupAddition =
      mpark::get<UserGroupAddition>(entry.action.variant());

  ensures(userGroupAddition.previousGroupBlock == group.lastBlockHash,
          Error::VerificationCode::InvalidGroup,
          "UserGroupAddition - previous group block does not match for this "
          "group id");

  ensures(Crypto::verify(userGroupAddition.signatureData(),
                         userGroupAddition.selfSignatureWithCurrentKey,
                         group.publicSignatureKey),
          Error::VerificationCode::InvalidSignature,
          "UserGroupAddition signature data must be signed with the group "
          "public key");
}
}
}
