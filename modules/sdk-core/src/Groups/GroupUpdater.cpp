#include <Tanker/Groups/GroupUpdater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <Tanker/Log.hpp>

TLOG_CATEGORY(GroupUpdater);

using Tanker::Trustchain::GroupId;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace GroupUpdater
{
namespace
{
struct MyGroupKey
{
  Crypto::EncryptionKeyPair userKeyPair;
  Crypto::SealedPrivateEncryptionKey encryptedPrivateEncryptionKey;
};

tc::cotask<nonstd::optional<MyGroupKey>> findMyKeys(
    UserKeyStore const& userKeyStore,
    UserGroupCreation1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    auto const matchingUserKeyPair =
        TC_AWAIT(userKeyStore.findKeyPair(gek.first));
    if (matchingUserKeyPair)
      TC_RETURN((MyGroupKey{
          *matchingUserKeyPair,
          gek.second,
      }));
  }
  TC_RETURN(nonstd::nullopt);
}

tc::cotask<void> putExternalGroup(GroupStore& groupStore,
                                  Entry const& entry,
                                  UserGroupCreation const& userGroupCreation)
{
  TC_AWAIT(groupStore.put(ExternalGroup{
      GroupId{userGroupCreation.publicSignatureKey()},
      userGroupCreation.publicSignatureKey(),
      userGroupCreation.sealedPrivateSignatureKey(),
      userGroupCreation.publicEncryptionKey(),
      entry.hash,
      entry.index,
  }));
}

tc::cotask<void> putFullGroup(GroupStore& groupStore,
                              MyGroupKey const& myKeys,
                              Entry const& entry,
                              UserGroupCreation const& userGroupCreation)
{
  auto const groupPrivateEncryptionKey =
      Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
          myKeys.encryptedPrivateEncryptionKey, myKeys.userKeyPair);
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt<Crypto::PrivateSignatureKey>(
          userGroupCreation.sealedPrivateSignatureKey(),
          Crypto::EncryptionKeyPair{
              userGroupCreation.publicEncryptionKey(),
              groupPrivateEncryptionKey,
          });
  TC_AWAIT(groupStore.put(Group{
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
  }));
}

tc::cotask<void> putFullGroup(GroupStore& groupStore,
                              ExternalGroup const& previousGroup,
                              MyGroupKey const& myKeys,
                              Entry const& entry)
{
  auto const groupPrivateEncryptionKey =
      Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
          myKeys.encryptedPrivateEncryptionKey, myKeys.userKeyPair);
  auto const groupPrivateSignatureKey =
      Crypto::sealDecrypt<Crypto::PrivateSignatureKey>(
          *previousGroup.encryptedPrivateSignatureKey,
          Crypto::EncryptionKeyPair{
              previousGroup.publicEncryptionKey,
              groupPrivateEncryptionKey,
          });
  TC_AWAIT(groupStore.put(Group{
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
  }));
}

tc::cotask<void> applyUserGroupCreation(GroupStore& groupStore,
                                        UserKeyStore const& userKeyStore,
                                        Entry const& entry)
{
  auto const& userGroupCreation = entry.action.get<UserGroupCreation>();

  auto const myKeys =
      TC_AWAIT(findMyKeys(userKeyStore,
                          userGroupCreation.get<UserGroupCreation1>()
                              .sealedPrivateEncryptionKeysForUsers()));

  if (!myKeys)
    TC_AWAIT(putExternalGroup(groupStore, entry, userGroupCreation));
  else
    TC_AWAIT(putFullGroup(groupStore, *myKeys, entry, userGroupCreation));
}

tc::cotask<void> applyUserGroupAddition(GroupStore& groupStore,
                                        UserKeyStore const& userKeyStore,
                                        Entry const& entry)
{
  auto const& userGroupAddition = entry.action.get<UserGroupAddition>();

  auto const previousGroup =
      TC_AWAIT(groupStore.findExternalById(userGroupAddition.groupId()));
  if (!previousGroup)
    throw Error::formatEx<std::runtime_error>(
        "assertion error: can't find previous group block for {}",
        userGroupAddition.groupId());

  TC_AWAIT(groupStore.updateLastGroupBlock(
      userGroupAddition.groupId(), entry.hash, entry.index));

  auto const myKeys =
      TC_AWAIT(findMyKeys(userKeyStore,
                          userGroupAddition.get<UserGroupAddition::v1>()
                              .sealedPrivateEncryptionKeysForUsers()));
  if (!myKeys)
    TC_RETURN();
  // I am already member of this group, ignore
  if (!previousGroup->encryptedPrivateSignatureKey)
    TC_RETURN();

  TC_AWAIT(putFullGroup(groupStore, *previousGroup, *myKeys, entry));
}
}

tc::cotask<void> applyEntry(GroupStore& groupStore,
                            UserKeyStore const& userKeyStore,
                            Entry const& entry)
{
  if (entry.action.holdsAlternative<UserGroupCreation>())
    TC_AWAIT(applyUserGroupCreation(groupStore, userKeyStore, entry));
  else if (entry.action.holdsAlternative<UserGroupAddition>())
    TC_AWAIT(applyUserGroupAddition(groupStore, userKeyStore, entry));
  else
    throw Error::formatEx<std::runtime_error>(
        "GroupUpdater can't handle this block (nature: {})", entry.nature);
}
}
}
