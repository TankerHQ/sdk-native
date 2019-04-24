#include <Tanker/TrustchainVerifier.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/User.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>
#include <Tanker/Verif/Helpers.hpp>
#include <Tanker/Verif/KeyPublishToDevice.hpp>
#include <Tanker/Verif/KeyPublishToUser.hpp>
#include <Tanker/Verif/KeyPublishToUserGroup.hpp>
#include <Tanker/Verif/ProvisionalIdentityClaim.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>
#include <Tanker/Verif/UserGroupAddition.hpp>
#include <Tanker/Verif/UserGroupCreation.hpp>

#include <cassert>

using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace
{
Entry toEntry(UnverifiedEntry const& e)
{
  return {e.index, e.nature, e.author, e.action, e.hash};
}

bool isDeviceCreation(Nature nature)
{
  return nature == Nature::DeviceCreation ||
         nature == Nature::DeviceCreation2 || nature == Nature::DeviceCreation3;
}
}

TrustchainVerifier::TrustchainVerifier(Trustchain::TrustchainId const& id,
                                       DataStore::ADatabase* db,
                                       ContactStore* contacts,
                                       GroupStore* groups)
  : _trustchainId(id), _db(db), _contacts(contacts), _groups(groups)
{
}

tc::cotask<Entry> TrustchainVerifier::verify(UnverifiedEntry const& e) const
{
  switch (e.nature)
  {
  case Nature::TrustchainCreation:
    Verif::verifyTrustchainCreation(e, _trustchainId);
    TC_RETURN(toEntry(e));
  case Nature::DeviceCreation:
  case Nature::DeviceCreation2:
  case Nature::DeviceCreation3:
    TC_RETURN(TC_AWAIT(handleDeviceCreation(e)));
  case Nature::KeyPublishToDevice:
  case Nature::KeyPublishToUser:
  case Nature::KeyPublishToProvisionalUser:
    TC_RETURN(TC_AWAIT(handleKeyPublish(e)));
  case Nature::KeyPublishToUserGroup:
    TC_RETURN(TC_AWAIT(handleKeyPublishToUserGroups(e)));
  case Nature::DeviceRevocation:
  case Nature::DeviceRevocation2:
    TC_RETURN(TC_AWAIT(handleDeviceRevocation(e)));
  case Nature::UserGroupAddition:
    TC_RETURN(TC_AWAIT(handleUserGroupAddition(e)));
  case Nature::UserGroupCreation:
    TC_RETURN(TC_AWAIT(handleUserGroupCreation(e)));
  case Nature::ProvisionalIdentityClaim:
    TC_RETURN(TC_AWAIT(handleProvisionalIdentityClaim(e)));
  }
  throw std::runtime_error(
      "Assertion failed: Invalid nature for unverified entry");
}

tc::cotask<Entry> TrustchainVerifier::handleDeviceCreation(
    UnverifiedEntry const& dc) const
{
  auto const author = TC_AWAIT(getAuthor(dc.author));

  switch (author.nature)
  {
  case Nature::TrustchainCreation:
  {
    Verif::verifyDeviceCreation(
        dc,
        mpark::get<Trustchain::Actions::TrustchainCreation>(
            author.action.variant()));
    break;
  }
  case Nature::DeviceCreation:
  case Nature::DeviceCreation2:
  case Nature::DeviceCreation3:
  {
    auto const& authorDeviceCreation =
        mpark::get<Trustchain::Actions::DeviceCreation>(
            author.action.variant());
    auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
    auto const authorDevice = getDevice(user, author.hash);
    Verif::verifyDeviceCreation(dc, authorDevice, user);
    break;
  }
  default:
    throw Error::VerificationFailed(Error::VerificationCode::InvalidAuthor,
                                    "Invalid author nature for deviceCreation");
  }
  TC_RETURN(toEntry(dc));
}

tc::cotask<Entry> TrustchainVerifier::handleKeyPublish(
    UnverifiedEntry const& kp) const
{
  auto const author = TC_AWAIT(getAuthor(kp.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for keyPublish");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(user, author.hash);
  if (kp.nature == Nature::KeyPublishToDevice)
  {
    Verif::verifyKeyPublishToDevice(kp, authorDevice, user);
  }
  else if (kp.nature == Nature::KeyPublishToUser ||
           kp.nature == Nature::KeyPublishToProvisionalUser)
  {
    Verif::verifyKeyPublishToUser(kp, authorDevice);
  }
  else
  {
    assert(false &&
           "nature must be "
           "KeyPublishToDevice/KeyPublishToUser/KeyPublishToProvisionalUser");
  }
  TC_RETURN(toEntry(kp));
}

tc::cotask<Entry> TrustchainVerifier::handleKeyPublishToUserGroups(
    UnverifiedEntry const& kp) const
{
  auto const author = TC_AWAIT(getAuthor(kp.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for keyPublish");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const& keyPublishToUserGroup =
      mpark::get<Trustchain::Actions::KeyPublishToUserGroup>(
          kp.action.variant());
  auto const group = TC_AWAIT(getGroupByEncryptionKey(
      keyPublishToUserGroup.recipientPublicEncryptionKey()));
  auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(user, author.hash);
  Verif::verifyKeyPublishToUserGroup(kp, authorDevice, group);

  TC_RETURN(toEntry(kp));
}

tc::cotask<Entry> TrustchainVerifier::handleDeviceRevocation(
    UnverifiedEntry const& dr) const
{
  auto const author = TC_AWAIT(getAuthor(dr.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for deviceRevocation");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const& revocation =
      mpark::get<Trustchain::Actions::DeviceRevocation>(dr.action.variant());
  auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(user, author.hash);
  auto const targetDevice =
      getDevice(user, static_cast<Crypto::Hash>(revocation.deviceId()));
  Verif::verifyDeviceRevocation(dr, authorDevice, targetDevice, user);

  TC_RETURN(toEntry(dr));
}

tc::cotask<Entry> TrustchainVerifier::handleUserGroupAddition(
    UnverifiedEntry const& ga) const
{
  auto const author = TC_AWAIT(getAuthor(ga.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for userGroupAddition");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const& userGroupAddition =
      mpark::get<UserGroupAddition>(ga.action.variant());
  auto const group = TC_AWAIT(getGroupById(userGroupAddition.groupId()));
  auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(user, author.hash);
  Verif::verifyUserGroupAddition(ga, authorDevice, group);

  TC_RETURN(toEntry(ga));
}

tc::cotask<Entry> TrustchainVerifier::handleUserGroupCreation(
    UnverifiedEntry const& gc) const
{
  auto const author = TC_AWAIT(getAuthor(gc.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for userGroupCreation");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const& userGroupCreation =
      mpark::get<Trustchain::Actions::UserGroupCreation>(gc.action.variant());
  auto const user = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(user, author.hash);

  auto const group = TC_AWAIT(_groups->findExternalByPublicEncryptionKey(
      userGroupCreation.publicEncryptionKey()));
  Verif::ensures(!group,
                 Error::VerificationCode::InvalidGroup,
                 "UserGroupCreation - group already exist");

  Verif::verifyUserGroupCreation(gc, authorDevice);

  TC_RETURN(toEntry(gc));
}

tc::cotask<Entry> TrustchainVerifier::handleProvisionalIdentityClaim(
    UnverifiedEntry const& claim) const
{
  auto const author = TC_AWAIT(getAuthor(claim.author));

  Verif::ensures(isDeviceCreation(author.nature),
                 Error::VerificationCode::InvalidAuthor,
                 "Invalid author nature for keyPublish");
  auto const& authorDeviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(author.action.variant());
  auto const authorUser = TC_AWAIT(getUser(authorDeviceCreation.userId()));
  auto const authorDevice = getDevice(authorUser, author.hash);
  Verif::verifyProvisionalIdentityClaim(claim, authorUser, authorDevice);

  TC_RETURN(toEntry(claim));
}

tc::cotask<Entry> TrustchainVerifier::getAuthor(
    Crypto::Hash const& authorHash) const
{
  auto const authorOpt = TC_AWAIT(_db->findTrustchainEntry(authorHash));
  Verif::ensures(authorOpt.has_value(),
                 Error::VerificationCode::InvalidAuthor,
                 "author not found");
  TC_RETURN(*authorOpt);
}

tc::cotask<User> TrustchainVerifier::getUser(UserId const& userId) const
{
  auto const user = TC_AWAIT(_contacts->findUser(userId));
  Verif::ensures(
      user.has_value(), Error::VerificationCode::InvalidUser, "user not found");
  TC_RETURN(*user);
}

Device TrustchainVerifier::getDevice(User const& user,
                                     Crypto::Hash const& deviceHash) const
{
  auto const device = std::find_if(
      user.devices.begin(), user.devices.end(), [&](auto const& device) {
        return device.id.base() == deviceHash.base();
      });
  assert(device != user.devices.end() && "device should belong to user");
  return *device;
}

tc::cotask<ExternalGroup> TrustchainVerifier::getGroupByEncryptionKey(
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  auto const group = TC_AWAIT(
      _groups->findExternalByPublicEncryptionKey(recipientPublicEncryptionKey));
  Verif::ensures(group.has_value(),
                 Error::VerificationCode::InvalidGroup,
                 "group not found");
  TC_RETURN(*group);
}

tc::cotask<ExternalGroup> TrustchainVerifier::getGroupById(
    Trustchain::GroupId const& groupId) const
{
  auto const group = TC_AWAIT(_groups->findExternalById(groupId));
  Verif::ensures(group.has_value(),
                 Error::VerificationCode::InvalidGroup,
                 "group not found");
  TC_RETURN(*group);
}
}
