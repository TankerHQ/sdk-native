#include <Tanker/TrustchainVerifier.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>

#include <cassert>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
TrustchainVerifier::TrustchainVerifier(Trustchain::TrustchainId const& id,
                                       Users::LocalUser* localUser,
                                       Users::ContactStore* contacts)
  : _trustchainId(id), _localUser(localUser), _contacts(contacts)
{
}

tc::cotask<Entry> TrustchainVerifier::verify(
    Trustchain::ServerEntry const& e) const
{
  switch (e.action().nature())
  {
  case Nature::TrustchainCreation:
    Verif::verifyTrustchainCreation(e, _trustchainId);
    TC_RETURN(Verif::makeVerifiedEntry(e));
  case Nature::DeviceCreation:
  case Nature::DeviceCreation2:
  case Nature::DeviceCreation3:
    TC_RETURN(TC_AWAIT(handleDeviceCreation(e)));
  case Nature::KeyPublishToDevice:
  case Nature::KeyPublishToUser:
  case Nature::KeyPublishToProvisionalUser:
  case Nature::KeyPublishToUserGroup:
    TC_RETURN(Verif::makeVerifiedEntry(e));
  case Nature::DeviceRevocation:
  case Nature::DeviceRevocation2:
    TC_RETURN(TC_AWAIT(handleDeviceRevocation(e)));
  case Nature::UserGroupAddition:
  case Nature::UserGroupAddition2:
  case Nature::UserGroupCreation:
  case Nature::UserGroupCreation2:
    throw Errors::AssertionError(
        fmt::format("group blocks are not handled by TrustchainVerifier "
                    "anymore (nature: {})",
                    e.action().nature()));
  case Nature::ProvisionalIdentityClaim:
    throw Errors::AssertionError(
        fmt::format("claim blocks are not handled by TrustchainVerifier "
                    "anymore (nature: {})",
                    e.action().nature()));
  }
  throw Errors::AssertionError(fmt::format(
      "invalid nature for unverified entry: {}", e.action().nature()));
}

tc::cotask<Entry> TrustchainVerifier::handleDeviceCreation(
    Trustchain::ServerEntry const& dc) const
{
  if (dc.author().base() == _trustchainId.base())
    Verif::verifyDeviceCreation(dc, _localUser->trustchainPublicSignatureKey());
  else
  {
    Users::User user;
    std::size_t idx;

    std::tie(user, idx) =
        TC_AWAIT(getUserByDeviceId(static_cast<DeviceId>(dc.author())));
    Verif::verifyDeviceCreation(
        dc, _trustchainId, _localUser->trustchainPublicSignatureKey(), user);
  }
  TC_RETURN(Verif::makeVerifiedEntry(dc));
}

tc::cotask<Entry> TrustchainVerifier::handleDeviceRevocation(
    Trustchain::ServerEntry const& dr) const
{
  auto const [user, idx] =
      TC_AWAIT(getUserByDeviceId(static_cast<DeviceId>(dr.author())));

  Verif::verifyDeviceRevocation(dr, user);

  TC_RETURN(Verif::makeVerifiedEntry(dr));
}

tc::cotask<Users::User> TrustchainVerifier::getUser(UserId const& userId) const
{
  auto const user = TC_AWAIT(_contacts->findUser(userId));
  Verif::ensures(user.has_value(), Verif::Errc::InvalidUser, "user not found");
  TC_RETURN(*user);
}

tc::cotask<std::pair<Users::User, std::size_t>>
TrustchainVerifier::getUserByDeviceId(
    Trustchain::DeviceId const& deviceId) const
{
  auto const optUserId = TC_AWAIT(_contacts->findUserIdByDeviceId(deviceId));

  Verif::ensures(
      optUserId.has_value(), Verif::Errc::InvalidAuthor, "user id not found");

  auto const user = TC_AWAIT(getUser(*optUserId));
  auto const deviceIt = std::find_if(
      user.devices.begin(), user.devices.end(), [&](auto const& device) {
        return device.id == deviceId;
      });
  assert(deviceIt != user.devices.end() && "device should belong to user");
  TC_RETURN(std::make_pair(
      user, static_cast<std::size_t>(deviceIt - user.devices.begin())));
}

Users::Device TrustchainVerifier::getDevice(Users::User const& user,
                                            DeviceId const& deviceId) const
{
  auto const device = std::find_if(
      user.devices.begin(), user.devices.end(), [&](auto const& device) {
        return device.id == deviceId;
      });
  assert(device != user.devices.end() && "device should belong to user");
  return *device;
}
}
