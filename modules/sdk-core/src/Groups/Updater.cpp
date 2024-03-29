#include <Tanker/Groups/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>

#include <Tanker/Groups/Verif/UserGroupAddition.hpp>
#include <Tanker/Groups/Verif/UserGroupCreation.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/Overloaded.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/UserAccessor.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <boost/container/flat_set.hpp>
#include <range/v3/algorithm/find.hpp>
#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

TLOG_CATEGORY(GroupUpdater);

using Tanker::Trustchain::GroupId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::GroupUpdater
{
namespace
{
std::optional<std::pair<Crypto::SealedPrivateEncryptionKey, Crypto::EncryptionKeyPair>> findUserKeyPair(
    gsl::span<Crypto::EncryptionKeyPair const> userKeys,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto myKeyIt = ranges::find(userKeys, gek.first, &Crypto::EncryptionKeyPair::publicKey);
        myKeyIt != userKeys.end())
      return std::make_pair(gek.second, *myKeyIt);
  }
  return std::nullopt;
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(
    Users::ILocalUserAccessor& localUserAccessor,
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const& groupKeys)
{
  auto userKeyPair = findUserKeyPair(localUserAccessor.get().userKeys(), groupKeys);
  if (!userKeyPair.has_value())
    userKeyPair = findUserKeyPair(TC_AWAIT(localUserAccessor.pull()).userKeys(), groupKeys);
  if (userKeyPair)
  {
    auto const [sealedKey, matchingUserKeyPair] = userKeyPair.value();
    auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(sealedKey, matchingUserKeyPair);
    TC_RETURN(groupPrivateEncryptionKey);
  }
  TC_RETURN(std::nullopt);
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyKey(Users::ILocalUserAccessor& localUserAccessor,
                                                                     UserGroupCreation::v2::Members const& groupKeys)
{
  auto const myId = localUserAccessor.get().userId();
  auto const myKeysIt = ranges::find(groupKeys, myId, &UserGroupMember2::userId);

  if (myKeysIt == groupKeys.end())
    TC_RETURN(std::nullopt);

  auto const userKeyPair = TC_AWAIT(localUserAccessor.pullUserKeyPair(myKeysIt->userPublicKey()));
  if (!userKeyPair)
  {
    throw AssertionError("group block does contains my user id but not my user key");
  }

  auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(myKeysIt->encryptedPrivateEncryptionKey(), *userKeyPair);
  TC_RETURN(groupPrivateEncryptionKey);
}

template <typename ProvMembers>
tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptMyProvisionalKey(
    ProvisionalUsers::IAccessor& provisionalUsersAccessor, ProvMembers const& groupKeys)
{
  for (auto const& gek : groupKeys)
  {
    if (auto const matchingProvisionalUserKeys = TC_AWAIT(provisionalUsersAccessor.findEncryptionKeysFromCache(
            gek.appPublicSignatureKey(), gek.tankerPublicSignatureKey())))
    {
      auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
          Crypto::sealDecrypt(gek.encryptedPrivateEncryptionKey(), matchingProvisionalUserKeys->tankerKeys),
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
                       Trustchain::getHash(userGroupCreation),
                       Trustchain::getHash(userGroupCreation)};
}

InternalGroup makeInternalGroup(Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
                                UserGroupCreation const& userGroupCreation)
{
  auto const groupPrivateSignatureKey = Crypto::sealDecrypt(userGroupCreation.sealedPrivateSignatureKey(),
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
                       Trustchain::getHash(userGroupCreation),
                       Trustchain::getHash(userGroupCreation)};
}

InternalGroup makeInternalGroup(ExternalGroup const& previousGroup,
                                Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
                                Trustchain::GroupAction const& action)
{
  auto const groupPrivateSignatureKey = Crypto::sealDecrypt(previousGroup.encryptedPrivateSignatureKey,
                                                            Crypto::EncryptionKeyPair{
                                                                previousGroup.publicEncryptionKey,
                                                                groupPrivateEncryptionKey,
                                                            });
  return InternalGroup{GroupId{previousGroup.publicSignatureKey},
                       Crypto::SignatureKeyPair{
                           previousGroup.publicSignatureKey,
                           groupPrivateSignatureKey,
                       },
                       Crypto::EncryptionKeyPair{
                           previousGroup.publicEncryptionKey,
                           groupPrivateEncryptionKey,
                       },
                       Trustchain::getHash(action),
                       previousGroup.lastKeyRotationBlockHash};
}

tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> decryptGroupPrivateEncryptionKey(
    Users::ILocalUserAccessor& localUserAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Trustchain::Actions::UserGroupAddition const& userGroupAddition)
{
  TC_RETURN(TC_AWAIT(userGroupAddition.visit(overloaded{
      [&](UserGroupAddition::v1 const& uga) -> tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> {
        TC_RETURN(TC_AWAIT(decryptMyKey(localUserAccessor, uga.sealedPrivateEncryptionKeysForUsers())));
      },
      [&](auto const& uga) -> tc::cotask<std::optional<Crypto::PrivateEncryptionKey>> {
        auto groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(localUserAccessor, uga.members()));
        if (!groupPrivateEncryptionKey)
          groupPrivateEncryptionKey =
              TC_AWAIT(decryptMyProvisionalKey(provisionalUsersAccessor, uga.provisionalMembers()));
        TC_RETURN(std::move(groupPrivateEncryptionKey));
      },
  })));
}
}

tc::cotask<Group> applyUserGroupCreation(Users::ILocalUserAccessor& localUserAccessor,
                                         ProvisionalUsers::IAccessor& provisionalUsersAccessor,
                                         Trustchain::GroupAction const& action)
{
  auto const& userGroupCreation = boost::variant2::get<UserGroupCreation>(action);

  std::optional<Crypto::PrivateEncryptionKey> groupPrivateEncryptionKey;
  TC_AWAIT(userGroupCreation.visit(overloaded{
      [&](UserGroupCreation::v1 const& ugc) -> tc::cotask<void> {
        groupPrivateEncryptionKey =
            TC_AWAIT(decryptMyKey(localUserAccessor, ugc.sealedPrivateEncryptionKeysForUsers()));
      },
      [&](auto const& ugc) -> tc::cotask<void> {
        groupPrivateEncryptionKey = TC_AWAIT(decryptMyKey(localUserAccessor, ugc.members()));
        if (!groupPrivateEncryptionKey)
          groupPrivateEncryptionKey =
              TC_AWAIT(decryptMyProvisionalKey(provisionalUsersAccessor, ugc.provisionalMembers()));
      },
  }));

  if (groupPrivateEncryptionKey)
    TC_RETURN(makeInternalGroup(*groupPrivateEncryptionKey, userGroupCreation));
  else
    TC_RETURN(makeExternalGroup(userGroupCreation));
}

tc::cotask<Group> applyUserGroupAddition(Users::ILocalUserAccessor& localUserAccessor,
                                         ProvisionalUsers::IAccessor& provisionalUsersAccessor,
                                         std::optional<Group> previousGroup,
                                         Trustchain::GroupAction const& action)
{
  auto const& userGroupAddition = boost::variant2::get<UserGroupAddition>(action);

  if (!previousGroup)
  {
    // this block should never have passed verification
    throw AssertionError(
        fmt::format(FMT_STRING("cannot find previous group block for {:s}"), userGroupAddition.groupId()));
  }

  updateLastGroupBlock(*previousGroup, Trustchain::getHash(action));

  // I am already member of this group, don't try to decrypt keys again
  if (auto ig = boost::variant2::get_if<InternalGroup>(&*previousGroup))
    TC_RETURN(std::move(*ig));

  auto const groupPrivateEncryptionKey =
      TC_AWAIT(decryptGroupPrivateEncryptionKey(localUserAccessor, provisionalUsersAccessor, userGroupAddition));

  // we checked above that this is an external group
  auto& externalGroup = boost::variant2::get<ExternalGroup>(*previousGroup);

  if (!groupPrivateEncryptionKey)
    TC_RETURN(std::move(externalGroup));
  else
    TC_RETURN(makeInternalGroup(externalGroup, *groupPrivateEncryptionKey, action));
}

namespace
{
class GroupEntryProcessor
{
public:
  GroupEntryProcessor(Users::ILocalUserAccessor* localUserAccessor,
                      ProvisionalUsers::IAccessor* provisionalUsersAccessor,
                      gsl::span<Users::Device const> authors,
                      std::optional<Group> group)
    : _localUserAccessor(localUserAccessor),
      _provisionalUsersAccessor(provisionalUsersAccessor),
      _authors(authors),
      _group(std::move(group))
  {
  }

  std::optional<Group> retrieveGroup() &&
  {
    return std::move(_group);
  }

  tc::cotask<void> operator()(UserGroupCreation const& userGroupCreation) const
  {
    auto const& author = getAuthor(userGroupCreation);
    auto const verifiedAction = Verif::verifyUserGroupCreation(userGroupCreation, author, extractBaseGroup(_group));
    _group = TC_AWAIT(applyUserGroupCreation(*_localUserAccessor, *_provisionalUsersAccessor, verifiedAction));
  }

  tc::cotask<void> operator()(UserGroupAddition const& userGroupAddition) const
  {
    auto const& author = getAuthor(userGroupAddition);
    auto const verifiedAction = Verif::verifyUserGroupAddition(userGroupAddition, author, extractBaseGroup(_group));
    _group = TC_AWAIT(
        applyUserGroupAddition(*_localUserAccessor, *_provisionalUsersAccessor, std::move(_group), verifiedAction));
  }

private:
  Users::Device const& getAuthor(Trustchain::GroupAction const& action) const
  {
    auto const author = static_cast<Trustchain::DeviceId>(Trustchain::getAuthor(action));
    auto const authorIt = ranges::find(_authors, author, &Users::Device::id);
    Verif::ensures(authorIt != _authors.end(), Verif::Errc::InvalidAuthor, "author not found");
    return *authorIt;
  }

  Users::ILocalUserAccessor* _localUserAccessor;
  ProvisionalUsers::IAccessor* _provisionalUsersAccessor;
  gsl::span<Users::Device const> _authors;
  std::optional<Group> mutable _group;
};

tc::cotask<std::optional<Group>> processGroupEntriesWithAuthors(std::vector<Users::Device> const& authors,
                                                                Users::ILocalUserAccessor& localUserAccessor,
                                                                ProvisionalUsers::IAccessor& provisionalUsersAccessor,
                                                                std::optional<Group> previousGroup,
                                                                gsl::span<Trustchain::GroupAction const> actions)
{
  GroupEntryProcessor processor{&localUserAccessor, &provisionalUsersAccessor, authors, std::move(previousGroup)};

  // could be an accumulate if cotasks were usable in ranges...
  for (auto const& action : actions)
    TC_AWAIT(boost::variant2::visit(processor, action));

  TC_RETURN(std::move(processor).retrieveGroup());
}
}

tc::cotask<std::optional<Group>> processGroupEntries(Users::ILocalUserAccessor& localUserAccessor,
                                                     Users::IUserAccessor& userAccessor,
                                                     ProvisionalUsers::IAccessor& provisionalUsersAccessor,
                                                     std::optional<Group> const& previousGroup,
                                                     gsl::span<Trustchain::GroupAction const> entries)
{
  auto authorIds =
      entries |
      ranges::views::transform([](auto const& action) { return Trustchain::DeviceId{Trustchain::getAuthor(action)}; }) |
      ranges::to<std::vector>;
  auto const devices = TC_AWAIT(userAccessor.pull(std::move(authorIds)));

  // We are going to process group entries in which there are provisional
  // identities. We can't know in advance if one of these identity is us or
  // not. That's why we pull all our claim blocks once here to know all our
  // provisional identities so that we can find if they are in the group or
  // not.
  TC_AWAIT(provisionalUsersAccessor.refreshKeys());
  TC_RETURN(TC_AWAIT(processGroupEntriesWithAuthors(
      devices.found, localUserAccessor, provisionalUsersAccessor, previousGroup, entries)));
}
}
