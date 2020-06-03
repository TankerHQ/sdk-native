#include <Tanker/Verif/DeviceCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Verif
{
namespace
{
bool verifySignature(DeviceCreation const& dc,
                     Crypto::PublicSignatureKey const& publicSignatureKey)
{
  auto const toVerify = dc.delegationSignatureData();
  return Crypto::verify(toVerify, dc.delegationSignature(), publicSignatureKey);
}

void verifySubAction(DeviceCreation::v1 const& deviceCreation,
                     Users::User const& user)
{
  ensures(!user.userKey().has_value(),
          Errc::InvalidUserKey,
          "A user must not have a user key to create a device creation v1");
}

void verifySubAction(DeviceCreation::v3 const& deviceCreation,
                     Users::User const& user)
{
  ensures(deviceCreation.publicUserEncryptionKey() == user.userKey(),
          Errc::InvalidUserKey,
          "DeviceCreation v3 must have the last user key");
}

DeviceCreation verifyDeviceCreation(DeviceCreation const& deviceCreation,
                                    Users::User const& user)
{
  auto authorDevice = user.findDevice(DeviceId{deviceCreation.author()});
  ensures(
      authorDevice.has_value(),
      Errc::InvalidUserId,
      "Device creation's user id must be the same than its parent device's");

  ensures(!authorDevice->isRevoked(),
          Errc::InvalidAuthor,
          "author device must not be revoked");

  assert(std::find(user.devices().begin(),
                   user.devices().end(),
                   *authorDevice) != user.devices().end());

  ensures(Crypto::verify(deviceCreation.hash(),
                         deviceCreation.signature(),
                         deviceCreation.ephemeralPublicSignatureKey()),
          Errc::InvalidSignature,
          "device creation block must be signed by the ephemeral private "
          "signature key");
  ensures(verifySignature(deviceCreation, authorDevice->publicSignatureKey()),
          Errc::InvalidDelegationSignature,
          "device creation's delegation signature must be signed by the "
          "author's private signature key");

  deviceCreation.visit(
      [&user](auto const& val) { verifySubAction(val, user); });
  return deviceCreation;
}
}

DeviceCreation verifyDeviceCreation(
    DeviceCreation const& deviceCreation,
    Crypto::PublicSignatureKey const& trustchainPublicSignatureKey)
{
  ensures(Crypto::verify(deviceCreation.hash(),
                         deviceCreation.signature(),
                         deviceCreation.ephemeralPublicSignatureKey()),
          Errc::InvalidSignature,
          "device creation block must be signed by the ephemeral private "
          "signature key");
  ensures(verifySignature(deviceCreation, trustchainPublicSignatureKey),
          Errc::InvalidDelegationSignature,
          "device creation's delegation signature must be signed by the "
          "author's private signature key");
  return deviceCreation;
}

DeviceCreation verifyDeviceCreation(DeviceCreation const& serverEntry,
                                    Trustchain::Context const& context,
                                    std::optional<Users::User> const& user)
{
  if (serverEntry.author().base() == context.id().base())
  {
    ensures(!user.has_value(),
            Errc::UserAlreadyExists,
            "Cannot have more than one device signed by the trustchain");
    return verifyDeviceCreation(serverEntry, context.publicSignatureKey());
  }
  else
  {
    ensures(user.has_value(), Errc::InvalidAuthor, "Author not found");
    return verifyDeviceCreation(serverEntry, user.value());
  }
}
}
}
