#include <Tanker/Groups/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>

#include <Tanker/Groups/Verif/UserGroupAddition.hpp>
#include <Tanker/Groups/Verif/UserGroupCreation.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/UserAccessor.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>

TLOG_CATEGORY(GroupUpdater);

using Tanker::Trustchain::GroupId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::GroupUpdater
{
namespace
{
std::optional<
    std::pair<Crypto::SealedPrivateEncryptionKey, Crypto::EncryptionKeyPair>>
findUserKeyPair(
    std::vector<Crypto::EncryptionKeyPair> const& userKeys,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto myKeyIt = std::find_if(userKeys.begin(),
                                    userKeys.end(),
                                    [&](auto const& userKey) {
                                      return gek.first == userKey.publicKey;
                                    });
        myKeyIt != userKeys.end())
      return std::make_pair(gek.second, *myKeyIt);
  }
  return std::nullopt;
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Users::ILocalUserAccessor& localUserAccessor,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  auto userKeyPair =
      findUserKeyPair(localUserAccessor.get().userKeys(), groupKeys);
  if (!userKeyPair.has_value())
    userKeyPair = findUserKeyPair(TC_AWAIT(localUserAccessor.pull()).userKeys(),
                                  groupKeys);
  if (userKeyPair)
  {
    auto const [sealedKey, matchingUserKeyPair] = userKeyPair.value();
    auto const groupPrivateEncryptionKey =
        Crypto::sealDecrypt(sealedKey, matchingUserKeyPair);
    TC_RETURN(groupPrivateEncryptionKey);
  }
  TC_RETURN(std::nullopt);
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Users::ILocalUserAccessor& localUserAccessor,
    UserGroupCreation::v2::Members const& groupKeys)
{
  auto const myKeysIt =
      std::find_if(groupKeys.begin(), groupKeys.end(), [&](auto const& k) {
        return k.userId() == localUserAccessor.get().userId();
      });
  if (myKeysIt == groupKeys.end())
    TC_RETURN(std::nullopt);

  auto const userKeyPair =
      TC_AWAIT(localUserAccessor.pullUserKeyPair(myKeysIt->userPublicKey()));
  if (!userKeyPair)
  {
    throw AssertionError(
        "group block does contains my user id but not my user key");
  }

  auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
      myKeysIt->encryptedPrivateEncryptionKey(), *userKeyPair);
  TC_RETURN(groupPrivateEncryptionKey);
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyProvisionalKey(
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    UserGroupCreation::v2::ProvisionalMembers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto const matchingProvisionalUserKeys =
            TC_AWAIT(provisionalUsersAccessor.findEncryptionKeysFromCache(
                gek.appPublicSignatureKey(), gek.tankerPublicSignatureKey())))
    {
      auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
          Crypto::sealDecrypt(gek.encryptedPrivateEncryptionKey(),
                              matchingProvisionalUserKeys->tankerKeys),
          matchingProvisionalUserKeys->appKeys);
      TC_RETURN(groupPrivateEncryptionKey);
    }
  }
  TC_RETURN(std::nullopt);
}

ExternalGroup makeExternalGroup(UserGroupCreation const& userGroupCreation)
{
  return ExternalGroup{GroupId{userGroupCreation.publicSignatureKey()},
                       userGroupCreation.publicSignatureKey(),
                       userGroupCreation.sealedPrivateSignatureKey(),
                       userGroupCreation.publicEncryptionKey(),
                       Trustchain::getHash(userGroupCreation)};
}

InternalGroup makeInternalGroup(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    UserGroupCreation const& userGroupCreation)
{
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt(userGroupCreation.sealedPrivateSignatureKey(),
                          Crypto::EncryptionKeyPair{
                              userGroupCreation.publicEncryptionKey(),
                              groupPrivateEncryptionKey,
                          });
  return InternalGroup{GroupId{userGroupCreation.publicSignatureKey()},
                       Crypto::SignatureKeyPair{
                           userGroupCreation.publicSignatureKey(),
                           groupPrivateSignatureKey,
                       },
                       Crypto::EncryptionKeyPair{
                           userGroupCreation.publicEncryptionKey(),
                           groupPrivateEncryptionKey,
                       },
                       Trustchain::getHash(userGroupCreation)};
}

InternalGroup makeInternalGroup(
    ExternalGroup const& previousGroup,
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    Trustchain::GroupAction const& action)
{
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt(previousGroup.encryptedPrivateSignatureKey,
                          Crypto::EncryptionKeyPair{
                              previousGroup.publicEncryptionKey,
                              groupPrivateEncryptionKey,
                          });
  return InternalGroup{
      GroupId{previousGroup.publicSignatureKey},
      Crypto::SignatureKeyPair{
          previousGroup.publicSignatureKey,
          groupPrivateSignatureKey,
      },
      Crypto::EncryptionKeyPair{
          previousGroup.publicEncryptionKey,
          groupPrivateEncryptionKey,
      },
      Trustchain::getHash(action),
  };
}
}

tc::cotask<Group> applyUserGroupCreation(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Trustchain::GroupAction const& action)
{
  auto const& userGroupCreation =
      boost::variant2::get<UserGroupCreation>(action);

  std::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const ugc1 = userGroupCreation.get_if<UserGroupCreation::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(
        localUserAccessor, ugc1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const ugc2 = userGroupCreation.get_if<UserGroupCreation::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(localUserAccessor, ugc2->members()));
    if (!groupPrivateEncryptionKey)
      groupPrivateEncryptionKey = TC_AWAIT(decryptMyProvisionalKey(
          provisionalUsersAccessor, ugc2->provisionalMembers()));
  }

  if (groupPrivateEncryptionKey)
    TC_RETURN(makeInternalGroup(*groupPrivateEncryptionKey, userGroupCreation));
  else
    TC_RETURN(makeExternalGroup(userGroupCreation));
}

tc::cotask<Group> applyUserGroupAddition(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Trustchain::GroupAction const& action)
{
  auto const& userGroupAddition =
      boost::variant2::get<UserGroupAddition>(action);

  if (!previousGroup)
  {
    // this block should never have passed verification
    throw AssertionError(
        fmt::format(FMT_STRING("cannot find previous group block for {:s}"),
                    userGroupAddition.groupId()));
  }

  updateLastGroupBlock(*previousGroup, Trustchain::getHash(action));

  // I am already member of this group, ignore
  if (boost::variant2::holds_alternative<InternalGroup>(*previousGroup))
    TC_RETURN(*previousGroup);

  std::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const uga1 = userGroupAddition.get_if<UserGroupAddition::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(
        localUserAccessor, uga1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const uga2 = userGroupAddition.get_if<UserGroupAddition::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(localUserAccessor, uga2->members()));
    if (!groupPrivateEncryptionKey)
      groupPrivateEncryptionKey = TC_AWAIT(decryptMyProvisionalKey(
          provisionalUsersAccessor, uga2->provisionalMembers()));
  }

  // we checked above that this is an external group
  auto& externalGroup = boost::variant2::get<ExternalGroup>(*previousGroup);

  if (!groupPrivateEncryptionKey)
    TC_RETURN(externalGroup);
  else
    TC_RETURN(
        makeInternalGroup(externalGroup, *groupPrivateEncryptionKey, action));
}

namespace
{
using DeviceMap =
    boost::container::flat_map<Trustchain::DeviceId, Users::Device>;

std::vector<Trustchain::DeviceId> extractAuthors(
    std::vector<Trustchain::GroupAction> const& entries)
{
  boost::container::flat_set<Trustchain::DeviceId> deviceIds;
  for (auto const& action : entries)
    deviceIds.insert(Trustchain::DeviceId(Trustchain::getAuthor(action)));
  return {deviceIds.begin(), deviceIds.end()};
}

tc::cotask<std::optional<Group>> processGroupEntriesWithAuthors(
    std::vector<Users::Device> const& authors,
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    std::vector<Trustchain::GroupAction> const& actions)
{
  for (auto const& action : actions)
  {
    try
    {
      auto const authorIt =
          std::find_if(authors.begin(), authors.end(), [&](auto const& device) {
            return Trustchain::getAuthor(action).base() == device.id().base();
          });
      Verif::ensures(authorIt != authors.end(),
                     Verif::Errc::InvalidAuthor,
                     "author not found");
      auto const& author = *authorIt;
      if (boost::variant2::holds_alternative<UserGroupCreation>(action))
      {
        auto const verifiedAction = Verif::verifyUserGroupCreation(
            action, author, extractBaseGroup(previousGroup));
        previousGroup = TC_AWAIT(applyUserGroupCreation(
            localUserAccessor, provisionalUsersAccessor, verifiedAction));
      }
      else if (boost::variant2::holds_alternative<UserGroupAddition>(action))
      {
        auto const verifiedAction = Verif::verifyUserGroupAddition(
            action, author, extractBaseGroup(previousGroup));
        previousGroup =
            TC_AWAIT(applyUserGroupAddition(localUserAccessor,
                                            provisionalUsersAccessor,
                                            previousGroup,
                                            verifiedAction));
      }
      else
        throw Errors::AssertionError(fmt::format(
            "cannot handle nature: {}", Trustchain::getNature(action)));
    }
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Verif::ErrcCategory())
      {
        TERROR("skipping invalid group block {}: {}",
               Trustchain::getHash(action),
               err.what());
      }
      else
        throw;
    }
  }
  TC_RETURN(previousGroup);
}
}

tc::cotask<std::optional<Group>> processGroupEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::GroupAction> const& entries)
{
  auto const authorIds = extractAuthors(entries);
  auto const devices = TC_AWAIT(userAccessor.pull(authorIds));

  // We are going to process group entries in which there are provisional
  // identities. We can't know in advance if one of these identity is us or
  // not. That's why we pull all our claim blocks once here to know all our
  // provisional identities so that we can find if they are in the group or
  // not.
  TC_AWAIT(provisionalUsersAccessor.refreshKeys());
  TC_RETURN(TC_AWAIT(processGroupEntriesWithAuthors(devices.found,
                                                    localUserAccessor,
                                                    provisionalUsersAccessor,
                                                    previousGroup,
                                                    entries)));
}
}
