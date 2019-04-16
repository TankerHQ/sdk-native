#include <Tanker/Verif/KeyPublishToUser.hpp>

#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/User.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
namespace Verif
{
void verifyKeyPublishToUser(UnverifiedEntry const& entry, Device const& author)
{
  assert(entry.nature == Nature::KeyPublishToUser);

  ensures(!author.revokedAtBlkIndex || author.revokedAtBlkIndex > entry.index,
          Error::VerificationCode::InvalidAuthor,
          "author device must not be revoked");
  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "KeyPublishToUser block must be signed by the author device");
}
}
}
