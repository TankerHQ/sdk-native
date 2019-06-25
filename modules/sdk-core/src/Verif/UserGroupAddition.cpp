#include <Tanker/Verif/UserGroupAddition.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
void verifyUserGroupAddition(ServerEntry const& serverEntry,
                             Device const& author,
                             ExternalGroup const& group)
{
  assert(serverEntry.action().nature() == Nature::UserGroupAddition ||
         serverEntry.action().nature() == Nature::UserGroupAddition2);

  ensures(!author.revokedAtBlkIndex ||
              author.revokedAtBlkIndex > serverEntry.index(),
          Errc::InvalidAuthor,
          "A revoked device must not be the author of a UserGroupAddition");

  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Errc::InvalidSignature,
          "UserGroupAddition block must be signed by the author device");

  auto const& userGroupAddition = serverEntry.action().get<UserGroupAddition>();

  ensures(userGroupAddition.previousGroupBlockHash() == group.lastBlockHash,
          Errc::InvalidGroup,
          "UserGroupAddition - previous group block does not match for this "
          "group id");

  ensures(Crypto::verify(userGroupAddition.signatureData(),
                         userGroupAddition.selfSignature(),
                         group.publicSignatureKey),
          Errc::InvalidSignature,
          "UserGroupAddition signature data must be signed with the group "
          "public key");
}
}
}
