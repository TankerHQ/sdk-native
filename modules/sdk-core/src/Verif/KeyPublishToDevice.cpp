#include <Tanker/Verif/KeyPublishToDevice.hpp>

#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/User.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

namespace Tanker
{
namespace Verif
{
void verifyKeyPublishToDevice(UnverifiedEntry const& entry,
                              Device const& author,
                              User const& recipientUser)
{
  assert(entry.nature == Nature::KeyPublishToDevice);

  ensures(!author.revokedAtBlkIndex,
          Error::VerificationCode::InvalidAuthor,
          "author device must not be revoked");
  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "keyPublishToDevice block must be signed by the author device");

  ensures(!recipientUser.userKey.has_value(),
          Error::VerificationCode::InvalidUserKey,
          "cannot KeyPublishToDevice to a device belonging to a user that has "
          "a userKey");
}
}
}
