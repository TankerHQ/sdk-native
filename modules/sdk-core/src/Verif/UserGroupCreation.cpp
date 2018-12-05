#include <Tanker/Verif/UserGroupCreation.hpp>

#include <Tanker/Actions/UserGroupCreation.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

namespace Tanker
{
namespace Verif
{
void verifyUserGroupCreation(UnverifiedEntry const& entry, Device const& author)
{
  assert(entry.nature == Nature::UserGroupCreation);

  ensures(!author.revokedAtBlkIndex,
          Error::VerificationCode::InvalidAuthor,
          "A revoked device must not be the author of UserGroupCreation");

  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "UserGroupCreation block must be signed by the author device");

  auto const& userGroupCreation =
      mpark::get<UserGroupCreation>(entry.action.variant());

  ensures(Crypto::verify(userGroupCreation.signatureData(),
                         userGroupCreation.selfSignature,
                         userGroupCreation.publicSignatureKey),
          Error::VerificationCode::InvalidSignature,
          "UserGroupCreation signature data must be signed with the group "
          "public key");
}
}
}
