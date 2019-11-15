#include <Tanker/Groups/GroupUpdater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Helpers.hpp>
#include <Tanker/Verif/UserGroupAddition.hpp>
#include <Tanker/Verif/UserGroupCreation.hpp>

#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>

TLOG_CATEGORY(GroupUpdater);

using Tanker::Trustchain::GroupId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker
{
namespace GroupUpdater
{
namespace
{
tc::cotask<nonstd::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    UserKeyStore const& userKeyStore,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto const matchingUserKeyPair =
            TC_AWAIT(userKeyStore.findKeyPair(gek.first)))
    {
      auto const groupPrivateEncryptionKey =
          Crypto::sealDecrypt(gek.second, *matchingUserKeyPair);
      TC_RETURN(groupPrivateEncryptionKey);
    }
  }
  TC_RETURN(nonstd::nullopt);
}

tc::cotask<nonstd::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Trustchain::UserId const& myUserId,
    UserKeyStore const& userKeyStore,
    UserGroupCreation::v2::Members const& groupKeys)
{
  auto const myKeysIt =
      std::find_if(groupKeys.begin(), groupKeys.end(), [&](auto const& k) {
        return k.userId() == myUserId;
      });
  if (myKeysIt == groupKeys.end())
    TC_RETURN(nonstd::nullopt);

  auto const userKeyPair =
      TC_AWAIT(userKeyStore.findKeyPair(myKeysIt->userPublicKey()));
  if (!userKeyPair)
  {
    throw AssertionError(
        "group block does contains my user id but not my user key");
  }

  auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
      myKeysIt->encryptedPrivateEncryptionKey(), *userKeyPair);
  TC_RETURN(groupPrivateEncryptionKey);
}

tc::cotask<nonstd::optional<Crypto::PrivateEncryptionKey>>
decryptMyProvisionalKey(
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    UserGroupCreation::v2::ProvisionalMembers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto const matchingProvisionalUserKeys =
            TC_AWAIT(provisionalUserKeysStore.findProvisionalUserKeys(
                gek.appPublicSignatureKey(), gek.tankerPublicSignatureKey())))
    {
      auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
          Crypto::sealDecrypt(gek.encryptedPrivateEncryptionKey(),
                              matchingProvisionalUserKeys->tankerKeys),
          matchingProvisionalUserKeys->appKeys);
      TC_RETURN(groupPrivateEncryptionKey);
    }
  }
  TC_RETURN(nonstd::nullopt);
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
    Trustchain::UserId const& myUserId,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Entry const& entry)
{
  auto const& userGroupCreation = entry.action.get<UserGroupCreation>();

  nonstd::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const ugc1 = userGroupCreation.get_if<UserGroupCreation::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(
        userKeyStore, ugc1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const ugc2 = userGroupCreation.get_if<UserGroupCreation::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(myUserId, userKeyStore, ugc2->members()));
    if (!groupPrivateEncryptionKey)
      groupPrivateEncryptionKey = TC_AWAIT(decryptMyProvisionalKey(
          provisionalUserKeysStore, ugc2->provisionalMembers()));
  }

  if (groupPrivateEncryptionKey)
    TC_RETURN(makeInternalGroup(
        *groupPrivateEncryptionKey, entry, userGroupCreation));
  else
    TC_RETURN(makeExternalGroup(entry, userGroupCreation));
}

tc::cotask<Group> applyUserGroupAddition(
    Trustchain::UserId const& myUserId,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    nonstd::optional<Group> previousGroup,
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

  nonstd::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  if (auto const uga1 = userGroupAddition.get_if<UserGroupAddition::v1>())
    groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(
        userKeyStore, uga1->sealedPrivateEncryptionKeysForUsers()));
  else if (auto const uga2 = userGroupAddition.get_if<UserGroupAddition::v2>())
  {
    groupPrivateEncryptionKey =
        TC_AWAIT(decryptMyKey(myUserId, userKeyStore, uga2->members()));
    if (!groupPrivateEncryptionKey)
      groupPrivateEncryptionKey = TC_AWAIT(decryptMyProvisionalKey(
          provisionalUserKeysStore, uga2->provisionalMembers()));
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
using DeviceMap = boost::container::flat_map<Trustchain::DeviceId, Device>;

tc::cotask<DeviceMap> extractAuthors(
    TrustchainPuller& trustchainPuller,
    ContactStore const& contactStore,
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
      out[Trustchain::DeviceId{entry.author()}] = *author;
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
        out[Trustchain::DeviceId{entry.author()}] = *author;
    }
  }

  TC_RETURN(out);
}

Entry toEntry(Trustchain::ServerEntry const& se)
{
  return {
      se.index(), se.action().nature(), se.author(), se.action(), se.hash()};
}

tc::cotask<nonstd::optional<Group>> processGroupEntriesWithAuthors(
    Trustchain::UserId const& myUserId,
    DeviceMap const& authors,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    nonstd::optional<Group> previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries)
{
  for (auto const& entry : entries)
  {
    auto const authorIt = authors.find(Trustchain::DeviceId{entry.author()});
    Verif::ensures(authorIt != authors.end(),
                   Verif::Errc::InvalidAuthor,
                   "author not found");
    auto const& author = authorIt->second;
    if (entry.action().holds_alternative<UserGroupCreation>())
    {
      Verif::verifyUserGroupCreation(
          entry, author, extractExternalGroup(previousGroup));
      previousGroup = TC_AWAIT(applyUserGroupCreation(
          myUserId, userKeyStore, provisionalUserKeysStore, toEntry(entry)));
    }
    else if (entry.action().holds_alternative<UserGroupAddition>())
    {
      Verif::ensures(previousGroup.has_value(),
                     Verif::Errc::InvalidGroup,
                     "UserGroupAddition references unknown group");
      Verif::verifyUserGroupAddition(
          entry, author, extractExternalGroup(*previousGroup));
      previousGroup = TC_AWAIT(applyUserGroupAddition(myUserId,
                                                      userKeyStore,
                                                      provisionalUserKeysStore,
                                                      previousGroup,
                                                      toEntry(entry)));
    }
    else
      throw Errors::AssertionError(
          fmt::format("cannot handle nature: {}", entry.action().nature()));
  }
  TC_RETURN(previousGroup);
}
}

tc::cotask<nonstd::optional<Group>> processGroupEntries(
    Trustchain::UserId const& myUserId,
    TrustchainPuller& trustchainPuller,
    ContactStore const& contactStore,
    UserKeyStore const& userKeyStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    nonstd::optional<Group> const& previousGroup,
    std::vector<Trustchain::ServerEntry> const& entries)
{
  auto const authors =
      TC_AWAIT(extractAuthors(trustchainPuller, contactStore, entries));
  TC_RETURN(TC_AWAIT(processGroupEntriesWithAuthors(myUserId,
                                                    authors,
                                                    userKeyStore,
                                                    provisionalUserKeysStore,
                                                    previousGroup,
                                                    entries)));
}
}
}
