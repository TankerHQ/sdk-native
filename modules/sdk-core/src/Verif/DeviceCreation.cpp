#include <Tanker/Verif/DeviceCreation.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Error.hpp>
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
namespace
{
void verifySubAction(DeviceCreation1 const& deviceCreation, User const& user)
{
  ensures(!user.userKey.has_value(),
          Error::VerificationCode::InvalidUserKey,
          "A user must not have a user key to create a device creation v1");
}

void verifySubAction(DeviceCreation3 const& deviceCreation, User const& user)
{
  ensures(deviceCreation.userKeyPair.publicEncryptionKey == user.userKey,
          Error::VerificationCode::InvalidUserKey,
          "DeviceCreation v3 must have the last user key");
}
}

void verifyDeviceCreation(UnverifiedEntry const& entry,
                          Device const& author,
                          User const& user)
{
  assert(entry.nature == Nature::DeviceCreation ||
         entry.nature == Nature::DeviceCreation3);

  ensures(!author.revokedAtBlkIndex || author.revokedAtBlkIndex > entry.index,
          Error::VerificationCode::InvalidAuthor,
          "author device must not be revoked");

  assert(std::find(user.devices.begin(), user.devices.end(), author) !=
         user.devices.end());

  auto const& deviceCreation =
      mpark::get<DeviceCreation>(entry.action.variant());

  ensures(Crypto::verify(entry.hash,
                         entry.signature,
                         deviceCreation.ephemeralPublicSignatureKey()),
          Error::VerificationCode::InvalidSignature,
          "device creation block must be signed by the ephemeral private "
          "signature key");
  ensures(verifyDelegationSignature(deviceCreation, author.publicSignatureKey),
          Error::VerificationCode::InvalidDelegationSignature,
          "device creation's delegation signature must be signed by the "
          "author's private signature key");

  ensures(
      deviceCreation.userId() == user.id,
      Error::VerificationCode::InvalidUserId,
      "Device creation's user id must be the same than its parent device's");
  mpark::visit([&](auto const& subAction) { verifySubAction(subAction, user); },
               deviceCreation.variant());
}

void verifyDeviceCreation(UnverifiedEntry const& entry,
                          TrustchainCreation const& author)
{
  assert(entry.nature == Nature::DeviceCreation ||
         entry.nature == Nature::DeviceCreation3);

  auto const& deviceCreation =
      mpark::get<DeviceCreation>(entry.action.variant());

  ensures(Crypto::verify(entry.hash,
                         entry.signature,
                         deviceCreation.ephemeralPublicSignatureKey()),
          Error::VerificationCode::InvalidSignature,
          "device creation block must be signed by the ephemeral private "
          "signature key");
  ensures(verifyDelegationSignature(deviceCreation, author.publicSignatureKey),
          Error::VerificationCode::InvalidDelegationSignature,
          "device creation's delegation signature must be signed by the "
          "author's private signature key");
}
}
}
