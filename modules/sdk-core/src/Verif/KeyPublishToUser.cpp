#include <Tanker/Verif/KeyPublishToUser.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/User.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
void verifyKeyPublishToUser(ServerEntry const& serverEntry,
                            Device const& author)
{
  assert(serverEntry.action().nature() == Nature::KeyPublishToUser ||
         serverEntry.action().nature() == Nature::KeyPublishToProvisionalUser);

  ensures(!author.revokedAtBlkIndex ||
              author.revokedAtBlkIndex > serverEntry.index(),
          Errc::InvalidAuthor,
          "author device must not be revoked");
  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Errc::InvalidSignature,
          "KeyPublishToUser block must be signed by the author device");
}
}
}
