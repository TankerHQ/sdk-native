#include <Tanker/Verif/KeyPublishToDevice.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToDevice.hpp>
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
void verifyKeyPublishToDevice(ServerEntry const& serverEntry,
                              Device const& author,
                              User const& recipientUser)
{
  assert(serverEntry.action().nature() == Nature::KeyPublishToDevice);

  ensures(!author.revokedAtBlkIndex ||
              author.revokedAtBlkIndex > serverEntry.index(),
          Errc::InvalidAuthor,
          "author device must not be revoked");
  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Errc::InvalidSignature,
          "keyPublishToDevice block must be signed by the author device");

  ensures(!recipientUser.userKey.has_value(),
          Errc::InvalidUserKey,
          "cannot KeyPublishToDevice to a device belonging to a user that has "
          "a userKey");
}
}
}
