#include <Tanker/Verif/ProvisionalIdentityClaim.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/User.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <mpark/variant.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
void verifyProvisionalIdentityClaim(ServerEntry const& serverEntry,
                                    User const& authorUser,
                                    Device const& author)
{
  assert(serverEntry.action().nature() == Nature::ProvisionalIdentityClaim);

  ensures(!author.revokedAtBlkIndex || author.revokedAtBlkIndex > serverEntry.index(),
          Error::VerificationCode::InvalidAuthor,
          "author device must not be revoked");
  ensures(Crypto::verify(serverEntry.hash(),
                         serverEntry.signature(),
                         author.publicSignatureKey),
          Error::VerificationCode::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the author device");

  auto const& provisionalIdentityClaim =
      serverEntry.action().get<ProvisionalIdentityClaim>();

  ensures(provisionalIdentityClaim.userId() == authorUser.id,
          Error::VerificationCode::InvalidUserId,
          "ProvisionalIdentityClaim's user ID does not match the author's one");

  ensures(
      provisionalIdentityClaim.userPublicEncryptionKey() == authorUser.userKey,
      Error::VerificationCode::InvalidUserKey,
      "ProvisionalIdentityClaim's user key does not match the user's one");

  auto const multiSignedPayload =
      provisionalIdentityClaim.signatureData(author.id);
  ensures(Crypto::verify(multiSignedPayload,
                         provisionalIdentityClaim.authorSignatureByAppKey(),
                         provisionalIdentityClaim.appSignaturePublicKey()),
          Error::VerificationCode::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the provisional "
          "app signature key");
  ensures(Crypto::verify(multiSignedPayload,
                         provisionalIdentityClaim.authorSignatureByTankerKey(),
                         provisionalIdentityClaim.tankerSignaturePublicKey()),
          Error::VerificationCode::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the provisional "
          "Tanker signature key");
}
}
}
