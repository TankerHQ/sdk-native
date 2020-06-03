#include <Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
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
ProvisionalIdentityClaim verifyProvisionalIdentityClaim(
    ProvisionalIdentityClaim const& provisionalIdentityClaim,
    Users::Device const& author)
{
  ensures(Crypto::verify(provisionalIdentityClaim.hash(),
                         provisionalIdentityClaim.signature(),
                         author.publicSignatureKey()),
          Errc::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the author device");

  ensures(provisionalIdentityClaim.userId() == author.userId(),
          Errc::InvalidUserId,
          "ProvisionalIdentityClaim's user ID does not match the author's one");

  auto const multiSignedPayload =
      provisionalIdentityClaim.signatureData(author.id());
  ensures(Crypto::verify(multiSignedPayload,
                         provisionalIdentityClaim.authorSignatureByAppKey(),
                         provisionalIdentityClaim.appSignaturePublicKey()),
          Errc::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the provisional "
          "app signature key");
  ensures(Crypto::verify(multiSignedPayload,
                         provisionalIdentityClaim.authorSignatureByTankerKey(),
                         provisionalIdentityClaim.tankerSignaturePublicKey()),
          Errc::InvalidSignature,
          "ProvisionalIdentityClaim block must be signed by the provisional "
          "Tanker signature key");

  return provisionalIdentityClaim;
}
}
}
