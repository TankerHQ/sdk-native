#include <Tanker/Verif/DeviceRevocation.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/DeviceRevocation.hpp>
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
template <typename T>
bool has_duplicates(std::vector<T> vect)
{
  std::sort(vect.begin(), vect.end());
  return std::adjacent_find(vect.begin(), vect.end()) != vect.end();
}

void verifySubAction(DeviceRevocation1 const& deviceRevocation,
                     Device const& target,
                     User const& user)
{
  ensures(!user.userKey,
          Error::VerificationCode::InvalidUserKey,
          "A revocation V1 cannot be used on an user with a user key");
}

void verifySubAction(DeviceRevocation2 const& deviceRevocation,
                     Device const& target,
                     User const& user)
{
  if (!user.userKey)
  {
    ensures(deviceRevocation.previousPublicEncryptionKey.is_null(),
            Error::VerificationCode::InvalidEncryptionKey,
            "A revocation V2 should have an empty previousPublicEncryptionKey "
            "when its user has no userKey");

    ensures(
        deviceRevocation.encryptedKeyForPreviousUserKey.is_null(),
        Error::VerificationCode::InvalidUserKey,
        "A revocation V2 should have an empty encryptedKeyForPreviousUserKey "
        "when its user has no userKey");
  }
  else
  {
    ensures(deviceRevocation.previousPublicEncryptionKey == *user.userKey,
            Error::VerificationCode::InvalidEncryptionKey,
            "A revocation V2 previousPublicEncryptionKey should be the same as "
            "its user userKey");
  }
  size_t const nbrDevicesNotRevoked = std::count_if(
      user.devices.begin(), user.devices.end(), [](auto const& device) {
        return device.revokedAtBlkIndex == nonstd::nullopt;
      });
  ensures(deviceRevocation.userKeys.size() == nbrDevicesNotRevoked - 1,
          Error::VerificationCode::InvalidUserKeys,
          "A revocation V2 should have exactly one userKey per remaining "
          "device of the user");
  for (auto userKey : deviceRevocation.userKeys)
  {
    ensures(userKey.deviceId != target.id,
            Error::VerificationCode::InvalidUserKeys,
            "A revocation V2 should not have the target deviceId in the "
            "userKeys field");

    ensures(std::find_if(user.devices.begin(),
                         user.devices.end(),
                         [&](auto const& device) {
                           return userKey.deviceId == device.id;
                         }) != user.devices.end(),
            Error::VerificationCode::InvalidUserKeys,
            "A revocation V2 should not have a key for another user's device");
  }

  ensures(!has_duplicates(deviceRevocation.userKeys),
          Error::VerificationCode::InvalidUserKeys,
          "A revocation V2 should not have duplicates entries in the userKeys "
          "field");
}
}

void verifyDeviceRevocation(UnverifiedEntry const& entry,
                            Device const& author,
                            Device const& target,
                            User const& user)
{
  assert(entry.nature == Nature::DeviceRevocation ||
         entry.nature == Nature::DeviceRevocation2);

  ensures(!author.revokedAtBlkIndex || author.revokedAtBlkIndex > entry.index,
          Error::VerificationCode::InvalidAuthor,
          "Author device of revocation must not be revoked");

  ensures(!target.revokedAtBlkIndex,
          Error::VerificationCode::InvalidTargetDevice,
          "The target of a revocation must not be already revoked");

  ensures(std::find(user.devices.begin(), user.devices.end(), author) !=
                  user.devices.end() &&
              std::find(user.devices.begin(), user.devices.end(), target) !=
                  user.devices.end(),
          Error::VerificationCode::InvalidUser,
          "A device can only be revoked by another device of its user");

  ensures(
      Crypto::verify(entry.hash, entry.signature, author.publicSignatureKey),
      Error::VerificationCode::InvalidSignature,
      "device revocation block must be signed by the public signature key of "
      "its author");

  auto const& deviceRevocation =
      mpark::get<DeviceRevocation>(entry.action.variant());

  mpark::visit(
      [&](auto const& subAction) { verifySubAction(subAction, target, user); },
      deviceRevocation.variant());
}
}
}
