#include <Tanker/Users/UserAccessor.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Users/Updater.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>

#include <range/v3/action/sort.hpp>
#include <range/v3/action/unique.hpp>
#include <range/v3/algorithm/unique.hpp>

#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(UserAccessor);

static constexpr auto ChunkSize = 100;

using boost::container::flat_map;

using Tanker::Trustchain::DeviceId;
using Tanker::Trustchain::UserId;

using PublicKeys = std::pair<Tanker::Crypto::PublicSignatureKey, Tanker::Crypto::PublicEncryptionKey>;

using namespace Tanker::Errors;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::Users
{

UserAccessor::UserAccessor(Trustchain::Context trustchainContext, Users::IRequester* requester)
  : _context(std::move(trustchainContext)), _requester(requester)
{
}

auto UserAccessor::pull(std::vector<UserId> userIds) -> tc::cotask<UserPullResult>
{
  TC_RETURN(TC_AWAIT((pullImpl<UserPullResult, UserId>(std::move(userIds)))));
}

auto UserAccessor::pull(std::vector<Trustchain::DeviceId> deviceIds)
    -> tc::cotask<DevicePullResult>
{
  TC_RETURN(TC_AWAIT((pullImpl<DevicePullResult, Trustchain::DeviceId>(std::move(deviceIds)))));
}

template <typename Result, typename Id>
auto UserAccessor::pullImpl(std::vector<Id> requestedIds) -> tc::cotask<Result>
{
  requestedIds |= Actions::deduplicate;

  auto const resultMap = TC_AWAIT(fetch(requestedIds));

  Result ret;
  ret.found.reserve(requestedIds.size());

  for (auto const& requestedId : requestedIds)
    if (auto it = resultMap.find(requestedId); it != resultMap.end())
      ret.found.push_back(it->second);
    else
      ret.notFound.push_back(requestedId);

  TC_RETURN(ret);
}

namespace
{
auto processUserEntries(Trustchain::Context const& context, gsl::span<Trustchain::UserAction const> actions)
{
  UsersMap usersMap;
  DevicesMap devicesMap;

  for (auto const& action : actions)
  {
    if (auto const dc = boost::variant2::get_if<DeviceCreation>(&action))
    {
      std::optional<Users::User> user;
      auto const userIt = usersMap.find(dc->userId());

      if (userIt != usersMap.end())
        user = userIt->second;

      auto const action = Verif::verifyDeviceCreation(*dc, context, user);

      user = Updater::applyDeviceCreationToUser(action, user);
      usersMap[dc->userId()] = *user;
      auto const& lastDevice = user->devices().back();
      if (auto const [it, isInserted] = devicesMap.emplace(lastDevice.id(), lastDevice); isInserted == false)
        throw Errors::AssertionError("DeviceCreation received more than once");
    }
    else
    {
      TERROR("Expected user blocks but got {}", Trustchain::getNature(action));
    }
  }
  return std::make_tuple(usersMap, devicesMap);
}

struct HashProvisionalUsersResult
{
  std::vector<HashedEmail> hashedEmails;
  std::vector<HashedPhoneNumber> hashedPhoneNumbers;
};

void hashProvisionalUser(Identity::PublicProvisionalIdentity const& identity, HashProvisionalUsersResult& result)
{
  switch (identity.target)
  {
  case Identity::TargetType::Email: {
    result.hashedEmails.push_back(Identity::hashProvisionalEmail(identity.value));
    break;
  }
  case Identity::TargetType::HashedEmail: {
    auto hashedEmail = mgs::base64::decode<HashedEmail>(identity.value);
    result.hashedEmails.push_back(hashedEmail);
    break;
  }
  case Identity::TargetType::HashedPhoneNumber: {
    auto hashedPhoneNumber = mgs::base64::decode<HashedPhoneNumber>(identity.value);
    result.hashedPhoneNumbers.push_back(hashedPhoneNumber);
    break;
  }
  default:
    throw AssertionError(fmt::format("unsupported target type: {}", static_cast<int>(identity.target)));
  }
}

HashProvisionalUsersResult hashProvisionalUsers(
    gsl::span<Identity::PublicProvisionalIdentity const> appProvisionalIdentities)
{
  HashProvisionalUsersResult result;
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
    hashProvisionalUser(appProvisionalIdentity, result);
  return result;
}

PublicKeys findFetchedPublicKeysForProvisional(
    Identity::PublicProvisionalIdentity const& appProvisionalIdentity,
    flat_map<HashedEmail, PublicKeys> const& tankerEmailProvisionalIdentities,
    flat_map<HashedPhoneNumber, PublicKeys> const& tankerPhoneNumberProvisionalIdentities)
{
  switch (appProvisionalIdentity.target)
  {
  case Identity::TargetType::HashedEmail: {
    auto const hashedValue = mgs::base64::decode<HashedEmail>(appProvisionalIdentity.value);
    auto const it = tankerEmailProvisionalIdentities.find(hashedValue);
    if (it == tankerEmailProvisionalIdentities.end())
      throw formatEx(Errc::InternalError,
                     "getPublicProvisionalIdentities is missing hashed email value {}",
                     appProvisionalIdentity.value);
    return it->second;
  }
  case Identity::TargetType::Email: {
    auto const it = tankerEmailProvisionalIdentities.find(Identity::hashProvisionalEmail(appProvisionalIdentity.value));
    if (it == tankerEmailProvisionalIdentities.end())
      throw formatEx(Errc::InternalError,
                     "getPublicProvisionalIdentities is missing email value {}",
                     // Avoid logging real emails directly
                     Identity::hashProvisionalEmail(appProvisionalIdentity.value));
    return it->second;
  }
  case Identity::TargetType::HashedPhoneNumber: {
    auto const hashedValue = mgs::base64::decode<HashedPhoneNumber>(appProvisionalIdentity.value);
    auto const it = tankerPhoneNumberProvisionalIdentities.find(hashedValue);
    if (it == tankerPhoneNumberProvisionalIdentities.end())
      throw formatEx(Errc::InternalError,
                     "getPublicProvisionalIdentities is missing hashed phone "
                     "number value {}",
                     appProvisionalIdentity.value);
    return it->second;
  }
  default:
    throw AssertionError(fmt::format("unexpected target ({})", appProvisionalIdentity.target));
  }
}

template <typename T>
void checkIdentityUnicity(std::vector<T> v)
{
  v |= ranges::actions::sort;
  if (ranges::unique(v) != v.end())
    throw formatEx(Errc::InvalidArgument, "using multiple provisional identities for the same target");
}
}

tc::cotask<std::vector<ProvisionalUsers::PublicUser>> UserAccessor::pullProvisional(
    std::vector<Identity::PublicProvisionalIdentity> appProvisionalIdentities)
{
  std::vector<ProvisionalUsers::PublicUser> provisionalUsers;

  if (appProvisionalIdentities.empty())
    TC_RETURN(provisionalUsers);

  constexpr auto proj = &Identity::PublicProvisionalIdentity::appSignaturePublicKey;

  appProvisionalIdentities |=
      ranges::actions::sort(ranges::less{}, proj) | ranges::actions::unique(ranges::equal_to{}, proj);

  auto const hashedProvisionals = hashProvisionalUsers(appProvisionalIdentities);
  checkIdentityUnicity(hashedProvisionals.hashedEmails);
  checkIdentityUnicity(hashedProvisionals.hashedPhoneNumbers);

  flat_map<HashedEmail, PublicKeys> tankerEmailProvisionalIdentities;
  for (unsigned int i = 0; i < hashedProvisionals.hashedEmails.size(); i += ChunkSize)
  {
    auto const count = std::min<unsigned int>(ChunkSize, hashedProvisionals.hashedEmails.size() - i);
    auto response = TC_AWAIT(
        _requester->getPublicProvisionalIdentities(gsl::make_span(hashedProvisionals.hashedEmails).subspan(i, count)));
    tankerEmailProvisionalIdentities.insert(std::make_move_iterator(response.begin()),
                                            std::make_move_iterator(response.end()));
  }

  flat_map<HashedPhoneNumber, PublicKeys> tankerPhoneNumberProvisionalIdentities;
  for (unsigned int i = 0; i < hashedProvisionals.hashedPhoneNumbers.size(); i += ChunkSize)
  {
    auto const count = std::min<unsigned int>(ChunkSize, hashedProvisionals.hashedPhoneNumbers.size() - i);
    auto response = TC_AWAIT(_requester->getPublicProvisionalIdentities(
        gsl::make_span(hashedProvisionals.hashedPhoneNumbers).subspan(i, count)));
    tankerPhoneNumberProvisionalIdentities.insert(std::make_move_iterator(response.begin()),
                                                  std::make_move_iterator(response.end()));
  }

  if (appProvisionalIdentities.size() !=
      tankerEmailProvisionalIdentities.size() + tankerPhoneNumberProvisionalIdentities.size())
  {
    throw formatEx(Errc::InternalError,
                   "getPublicProvisionalIdentities returned a list of "
                   "different size ({} vs. {})",
                   appProvisionalIdentities.size(),
                   tankerEmailProvisionalIdentities.size() + tankerPhoneNumberProvisionalIdentities.size());
  }

  provisionalUsers.reserve(appProvisionalIdentities.size());
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
  {
    auto publicKeys = findFetchedPublicKeysForProvisional(
        appProvisionalIdentity, tankerEmailProvisionalIdentities, tankerPhoneNumberProvisionalIdentities);
    provisionalUsers.push_back({appProvisionalIdentity.appSignaturePublicKey,
                                appProvisionalIdentity.appEncryptionPublicKey,
                                publicKeys.first,
                                publicKeys.second});
  }

  TC_RETURN(provisionalUsers);
}

auto UserAccessor::fetch(gsl::span<Trustchain::UserId const> userIds)
    -> tc::cotask<UsersMap>
{
  TC_RETURN(TC_AWAIT(fetchImpl<UsersMap>(userIds)));
}

auto UserAccessor::fetch(gsl::span<Trustchain::DeviceId const> deviceIds)
    -> tc::cotask<DevicesMap>
{
  TC_RETURN(TC_AWAIT(fetchImpl<DevicesMap>(deviceIds)));
}

template <typename Result, typename Id>
auto UserAccessor::fetchImpl(gsl::span<Id const> ids) -> tc::cotask<Result>
{
  Result out;

  if (ids.empty())
    TC_RETURN(out);

  out.reserve(ids.size());
  for (unsigned int i = 0; i < ids.size(); i += ChunkSize)
  {
    auto const count = std::min<std::size_t>(ChunkSize, ids.size() - i);
    auto const [trustchainCreation, actions] = TC_AWAIT(_requester->getUsers(ids.subspan(i, count)));
    auto currentUsers = std::get<Result>(processUserEntries(_context, actions));
    out.insert(std::make_move_iterator(currentUsers.begin()), std::make_move_iterator(currentUsers.end()));
  }
  TC_RETURN(out);
}
}
