#include <Tanker/Verif/KeyPublishToUserGroup.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Trustchain;

namespace Tanker
{
namespace Verif
{
void verifyKeyPublishToUserGroup(ServerEntry const& serverEntry,
                                 Device const& author,
                                 ExternalGroup const& recipientGroup)
{
  assert(serverEntry.action().nature() == Nature::KeyPublishToUserGroup);

  assert(recipientGroup.publicEncryptionKey ==
         serverEntry.action()
             .get<KeyPublish>()
             .get<KeyPublish::ToUserGroup>()
             .recipientPublicEncryptionKey());

  ensures(!author.revokedAtBlkIndex ||
              author.revokedAtBlkIndex > serverEntry.index(),
          Errc::InvalidAuthor,
          "author device must not be revoked");
  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Errc::InvalidSignature,
          "keyPublishToUserGroup block must be signed by the author device");
}
}
}
