#include <Tanker/Groups/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/Verif/UserGroupAddition.hpp>
#include <Tanker/Groups/Verif/UserGroupCreation.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/LocalUser.hpp>
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
tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Users::LocalUser const& localUser,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto const matchingUserKeyPair =
            TC_AWAIT(localUser.findKeyPair(gek.first)))
    {
      auto const groupPrivateEncryptionKey =
          Crypto::sealDecrypt(gek.second, *matchingUserKeyPair);
      TC_RETURN(groupPrivateEncryptionKey);
    }
  }
  TC_RETURN(std::nullopt);
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Users::LocalUser const& localUser,
    UserGroupCreation::v2::Members const& groupKeys)
{
  auto const myKeysIt =
      std::find_if(groupKeys.begin(), groupKeys.end(), [&](auto const& k) {
        return k.userId() == localUser.userId();
      });
  if (myKeysIt == groupKeys.end())
    TC_RETURN(std::nullopt);

  auto const userKeyPair =
      TC_AWAIT(localUser.findKeyPair(myKeysIt->userPublicKey()));
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

ExternalGroup makeExternalGroup(Entry const& entry,
                                UserGroupCreation const& userGroupCreation)
{
  return ExternalGroup{
      GroupId{userGroupCreation.publicSignatureKey()},
      userGroupCreation.publicSignatureKey(),
      userGroupCreation.sealedPrivateSignatureKey(),
      userGroupCreation.publicEncryptionKey(),
      entry.hash,
      entry.index,
  };
}

InternalGroup makeInternalGroup(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    Entry const& entry,
    UserGroupCreation const& userGroupCreation)
{
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt(userGroupCreation.sealedPrivateSignatureKey(),
                          Crypto::EncryptionKeyPair{
                              userGroupCreation.publicEncryptionKey(),
                              groupPrivateEncryptionKey,
                          });
  return InternalGroup{
      GroupId{userGroupCreation.publicSignatureKey()},
      Crypto::SignatureKeyPair{
          userGroupCreation.publicSignatureKey(),
          groupPrivateSignatureKey,
      },
      Crypto::EncryptionKeyPair{
          userGroupCreation.publicEncryptionKey(),
          groupPrivateEncryptionKey,
      },
      entry.hash,
      entry.index,
  };
}

InternalGroup makeInternalGroup(
    ExternalGroup const& previousGroup,
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    Entry const& entry)
{
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt(*previousGroup.encryptedPrivateSignatureKey,
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
      entry.hash,
      entry.index,
  };
}
}

tc::cotask<Group> applyUserGroupCreation(
    Users::LocalUser const& localUser,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Entry const& entry)
{
  auto const& userGroupCreation = entry.action.get<UserGroupCreation>();

  std::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const ugc1 = userGroupCreation.get_if<UserGroupCreation::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(
        decryptMyKey(localUser, ugc1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const ugc2 = userGroupCreation.get_if<UserGroupCreation::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(localUser, ugc2->members()));
    if (!groupPrivateEncryptionKey)
      groupPrivateEncryptionKey = TC_AWAIT(decryptMyProvisionalKey(
          provisionalUsersAccessor, ugc2->provisionalMembers()));
  }

  if (groupPrivateEncryptionKey)
    TC_RETURN(makeInternalGroup(
        *groupPrivateEncryptionKey, entry, userGroupCreation));
  else
    TC_RETURN(makeExternalGroup(entry, userGroupCreation));
}

tc::cotask<Group> applyUserGroupAddition(
    Users::LocalUser const& localUser,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    Entry const& entry)
{
  auto const& userGroupAddition = entry.action.get<UserGroupAddition>();

  if (!previousGroup)
  {
    // this block should never have passed verification
    throw AssertionError(
        fmt::format(TFMT("cannot find previous group block for {:s}"),
                    userGroupAddition.groupId()));
  }

  updateLastGroupBlock(*previousGroup, entry.hash, entry.index);

  // I am already member of this group, ignore
  if (boost::variant2::holds_alternative<InternalGroup>(*previousGroup))
    TC_RETURN(*previousGroup);

  std::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const uga1 = userGroupAddition.get_if<UserGroupAddition::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(
        decryptMyKey(localUser, uga1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const uga2 = userGroupAddition.get_if<UserGroupAddition::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(localUser, uga2->members()));
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
        makeInternalGroup(externalGroup, *groupPrivateEncryptionKey, entry));
}

namespace
{
using DeviceMap =
    boost::container::flat_map<Trustchain::DeviceId, Users::Device>;

tc::cotask<DeviceMap> extractAuthors(
    ITrustchainPuller& trustchainPuller,
    Users::ContactStore const& contactStore,
    std::vector<Trustchain::ServerEntry> const& entries)
{
  DeviceMap out;

  // There is no way to pull users by device id, so for the moment we pull the
  // whole group through a hack that gives us all authors without the
  // groups themselves. This will disappear once we have that new route.
  boost::container::flat_set<Trustchain::GroupId> groupsToPull;

  for (auto const& entry : entries)
  {
    if (out.find(Trustchain::DeviceId{entry.author()}) != out.end())
      continue;

    auto const author =
        TC_AWAIT(contactStore.findDevice(Trustchain::DeviceId{entry.author()}));
    if (author)
    {
      auto [it, isInserted] =
          out.emplace(Trustchain::DeviceId{entry.author()}, *author);
      assert(isInserted);
    }
    else
    {
      if (auto const userGroupCreation =
              entry.action().get_if<UserGroupCreation>())
        groupsToPull.insert(GroupId{userGroupCreation->publicSignatureKey()});
      else if (auto const userGroupAddition =
                   entry.action().get_if<UserGroupAddition>())
        groupsToPull.insert(userGroupAddition->groupId());
      else
        throw Errors::AssertionError(
            fmt::format("cannot handle nature: {}", entry.action().nature()));
    }
  }

  if (!groupsToPull.empty())
  {
    std::vector<Trustchain::GroupId> vgroupsToPull(groupsToPull.begin(),
                                                   groupsToPull.end());
    TC_AWAIT(trustchainPuller.scheduleCatchUp({}, vgroupsToPull));

    for (auto const& entry : entries)
    {
      if (out.find(Trustchain::DeviceId{entry.author()}) != out.end())
        continue;

      auto const author = TC_AWAIT(
          contactStore.findDevice(Trustchain::DeviceId{entry.author()}));
      if (author)
      {
        auto [it, isInserted] =
            out.emplace(Trustchain::DeviceId{entry.author()}, *author);
        assert(isInserted);
      }
    }
  }

  TC_RETURN(out);
}

tc::cotask<std::optional<Group>> processGroupEntriesWithAuthors(
    DeviceMap const& authors,
    Users::LocalUser const& localUser,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> previousGroup,
    std::vector<Trustchain::ServerEntry> const& serverEntries)
{
  for (auto const& serverEntry : serverEntries)
  {
    try
    {
      auto const authorIt =
          authors.find(Trustchain::DeviceId{serverEntry.author()});
      Verif::ensures(authorIt != authors.end(),
                     Verif::Errc::InvalidAuthor,
                     "author not found");
      auto const& author = authorIt->second;
      if (serverEntry.action().holds_alternative<UserGroupCreation>())
      {
        auto const entry = Verif::verifyUserGroupCreation(
            serverEntry, author, extractExternalGroup(previousGroup));
        previousGroup = TC_AWAIT(
            applyUserGroupCreation(localUser, provisionalUsersAccessor, entry));
      }
      else if (serverEntry.action().holds_alternative<UserGroupAddition>())
      {
        auto const entry = Verif::verifyUserGroupAddition(
            serverEntry, author, extractExternalGroup(previousGroup));
        previousGroup = TC_AWAIT(applyUserGroupAddition(
            localUser, provisionalUsersAccessor, previousGroup, entry));
      }
      else
        throw Errors::AssertionError(fmt::format(
            "cannot handle nature: {}", serverEntry.action().nature()));
    }
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Verif::ErrcCategory())
      {
        TERROR("skipping invalid group block {}: {}",
               serverEntry.hash(),
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
    ITrustchainPuller& trustchainPuller,
    Users::LocalUser const& localUser,
    Users::ContactStore const& contactStore,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    std::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries)
{
  auto const authors =
      TC_AWAIT(extractAuthors(trustchainPuller, contactStore, entries));
  // We are going to process group entries in which there are provisional
  // identities. We can't know in advance if one of these identity is us or not.
  // That's why we pull all our claim blocks once here to know all our
  // provisional identities so that we can find if they are in the group or not.
  TC_AWAIT(provisionalUsersAccessor.refreshKeys());
  TC_RETURN(TC_AWAIT(processGroupEntriesWithAuthors(
      authors, localUser, provisionalUsersAccessor, previousGroup, entries)));
}
}
