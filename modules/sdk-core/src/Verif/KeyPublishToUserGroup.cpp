#include <Tanker/Verif/KeyPublishToUserGroup.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
namespace Verif
{
void verifyKeyPublishToUserGroup(UnverifiedEntry const& entry,
                                 Device const& author,
                                 ExternalGroup const& recipientGroup)
{
  assert(entry.nature == Nature::KeyPublishToUserGroup);

  assert(recipientGroup.publicEncryptionKey ==
         mpark::get<KeyPublishToUserGroup>(entry.action.variant())
             .recipientPublicEncryptionKey);

  ensures(!author.revokedAtBlkIndex || author.revokedAtBlkIndex > entry.index,
          Error::VerificationCode::InvalidAuthor,
          "author device must not be revoked");
  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "keyPublishToUserGroup block must be signed by the author device");
}
}
}
