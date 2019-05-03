#include <Tanker/Verif/UserGroupCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
void verifyUserGroupCreation(ServerEntry const& serverEntry, Device const& author)
{
  assert(serverEntry.action().nature() == Nature::UserGroupCreation);

  ensures(!author.revokedAtBlkIndex ||
              author.revokedAtBlkIndex > serverEntry.index(),
          Error::VerificationCode::InvalidAuthor,
          "A revoked device must not be the author of UserGroupCreation");

  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Error::VerificationCode::InvalidSignature,
          "UserGroupCreation block must be signed by the author device");

  auto const& userGroupCreation = serverEntry.action().get<UserGroupCreation>();

  ensures(Crypto::verify(userGroupCreation.signatureData(),
                         userGroupCreation.selfSignature(),
                         userGroupCreation.publicSignatureKey()),
          Error::VerificationCode::InvalidSignature,
          "UserGroupCreation signature data must be signed with the group "
          "public key");
}
}
}
