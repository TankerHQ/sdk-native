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
Entry verifyUserGroupCreation(ServerEntry const& serverEntry,
                              Users::Device const& author,
                              std::optional<ExternalGroup> const& previousGroup)
{
  assert(serverEntry.action().nature() == Nature::UserGroupCreation ||
         serverEntry.action().nature() == Nature::UserGroupCreation2);

  ensures(!previousGroup,
          Verif::Errc::InvalidGroup,
          "UserGroupCreation - group already exist");

  ensures(!author.revokedAtBlkIndex() ||
              author.revokedAtBlkIndex() > serverEntry.index(),
          Errc::InvalidAuthor,
          "A revoked device must not be the author of UserGroupCreation");

  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey()),
          Errc::InvalidSignature,
          "UserGroupCreation block must be signed by the author device");

  auto const& userGroupCreation = serverEntry.action().get<UserGroupCreation>();

  ensures(Crypto::verify(userGroupCreation.signatureData(),
                         userGroupCreation.selfSignature(),
                         userGroupCreation.publicSignatureKey()),
          Errc::InvalidSignature,
          "UserGroupCreation signature data must be signed with the group "
          "public key");

  return makeVerifiedEntry(serverEntry);
}
}
}
