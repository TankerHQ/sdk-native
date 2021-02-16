#include <Tanker/Users/UserAccessor.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Users/Updater.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>

#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(UserAccessor);

static constexpr auto ChunkSize = 100;

using Tanker::Trustchain::DeviceId;
using Tanker::Trustchain::UserId;

using namespace Tanker::Errors;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::Users
{

UserAccessor::UserAccessor(Trustchain::Context trustchainContext,
                           Users::IRequester* requester)
  : _context(std::move(trustchainContext)), _requester(requester)
{
}

auto UserAccessor::pull(std::vector<UserId> userIds)
    -> tc::cotask<UserPullResult>
{
  return pullImpl<UserPullResult, UserId>(std::move(userIds));
}

auto UserAccessor::pull(std::vector<Trustchain::DeviceId> deviceIds)
    -> tc::cotask<DevicePullResult>
{
  return pullImpl<DevicePullResult, Trustchain::DeviceId>(std::move(deviceIds));
}

template <typename Result, typename Id>
auto UserAccessor::pullImpl(std::vector<Id> requestedIds) -> tc::cotask<Result>
{
  std::sort(requestedIds.begin(), requestedIds.end());
  requestedIds.erase(std::unique(requestedIds.begin(), requestedIds.end()),
                     requestedIds.end());

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
Users::User* findUserOfDevice(DevicesMap const& devicesMap,
                              UsersMap& usersMap,
                              Trustchain::DeviceId const& deviceId)
{
  auto const deviceIt = devicesMap.find(deviceId);
  if (deviceIt == devicesMap.end())
    return nullptr;
  auto const userIt = usersMap.find(deviceIt->second.userId());
  if (userIt == usersMap.end())
    return nullptr;
  return &userIt->second;
}

auto processUserEntries(Trustchain::Context const& context,
                        gsl::span<Trustchain::UserAction const> actions)
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
      if (auto const [it, isInserted] =
              devicesMap.emplace(lastDevice.id(), lastDevice);
          isInserted == false)
        throw Errors::AssertionError("DeviceCreation received more than once");
    }
    else if (auto const deviceRevocation =
                 boost::variant2::get_if<DeviceRevocation>(&action))
    {
      auto const user =
          findUserOfDevice(devicesMap, usersMap, deviceRevocation->deviceId());
      auto const action = Verif::verifyDeviceRevocation(
          *deviceRevocation, user ? std::make_optional(*user) : std::nullopt);
      if (!user)
        throw Errors::AssertionError(
            "user not found, verification should have failed");

      *user = Updater::applyDeviceRevocationToUser(action, *user);
    }
    else
    {
      TERROR("Expected user blocks but got {}", Trustchain::getNature(action));
    }
  }
  return std::make_tuple(usersMap, devicesMap);
}

Crypto::Hash hashEmail(Email const& email)
{
  return Crypto::generichash(
      gsl::make_span(email).template as_span<std::uint8_t const>());
}

std::vector<Crypto::Hash> hashProvisionalUserEmails(

    gsl::span<Identity::PublicProvisionalIdentity const>
        appProvisionalIdentities)
{
  std::vector<Crypto::Hash> hashedProvisionalUserEmails;
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
  {
    if (appProvisionalIdentity.target != Identity::TargetType::Email)
    {
      throw AssertionError(
          fmt::format("unsupported target type: {}",
                      static_cast<int>(appProvisionalIdentity.target)));
    }
    hashedProvisionalUserEmails.push_back(
        hashEmail(Email{appProvisionalIdentity.value}));
  }
  return hashedProvisionalUserEmails;
}
}

tc::cotask<std::vector<ProvisionalUsers::PublicUser>>
UserAccessor::pullProvisional(
    std::vector<Identity::PublicProvisionalIdentity> appProvisionalIdentities)
{
  std::vector<ProvisionalUsers::PublicUser> provisionalUsers;
  if (appProvisionalIdentities.empty())
    TC_RETURN(provisionalUsers);

  std::sort(appProvisionalIdentities.begin(),
            appProvisionalIdentities.end(),
            [](auto const& a, auto const& b) {
              return a.appSignaturePublicKey < b.appSignaturePublicKey;
            });
  appProvisionalIdentities.erase(std::unique(appProvisionalIdentities.begin(),
                                             appProvisionalIdentities.end(),
                                             [](auto const& a, auto const& b) {
                                               return a.appSignaturePublicKey ==
                                                      b.appSignaturePublicKey;
                                             }),
                                 appProvisionalIdentities.end());

  auto const hashedEmails = hashProvisionalUserEmails(appProvisionalIdentities);

  std::map<Crypto::Hash,
           std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      tankerProvisionalIdentities;
  for (unsigned int i = 0; i < hashedEmails.size(); i += ChunkSize)
  {
    auto const count =
        std::min<unsigned int>(ChunkSize, hashedEmails.size() - i);
    auto response = TC_AWAIT(_requester->getPublicProvisionalIdentities(
        gsl::make_span(hashedEmails).subspan(i, count)));
    tankerProvisionalIdentities.insert(
        std::make_move_iterator(response.begin()),
        std::make_move_iterator(response.end()));
  }

  if (appProvisionalIdentities.size() != tankerProvisionalIdentities.size())
  {
    throw formatEx(Errc::InternalError,
                   "getPublicProvisionalIdentities returned a list of "
                   "different size ({} vs. {})",
                   appProvisionalIdentities.size(),
                   tankerProvisionalIdentities.size());
  }

  provisionalUsers.reserve(appProvisionalIdentities.size());
  for (auto i = 0u; i < appProvisionalIdentities.size(); ++i)
  {
    auto const& [tankerSigKey, tankerEncKey] =
        tankerProvisionalIdentities.at(hashedEmails[i]);
    provisionalUsers.push_back(
        {appProvisionalIdentities[i].appSignaturePublicKey,
         appProvisionalIdentities[i].appEncryptionPublicKey,
         tankerSigKey,
         tankerEncKey});
  }

  TC_RETURN(provisionalUsers);
}

auto UserAccessor::fetch(gsl::span<Trustchain::UserId const> userIds)
    -> tc::cotask<UsersMap>
{
  if (userIds.empty())
    TC_RETURN(UsersMap{});

  UsersMap out;
  out.reserve(userIds.size());
  for (unsigned int i = 0; i < userIds.size(); i += ChunkSize)
  {
    auto const count = std::min<std::size_t>(ChunkSize, userIds.size() - i);
    auto const [trustchainCreation, actions] =
        TC_AWAIT(_requester->getUsers(userIds.subspan(i, count)));
    auto currentUsers =
        std::get<UsersMap>(processUserEntries(_context, actions));
    out.insert(std::make_move_iterator(currentUsers.begin()),
               std::make_move_iterator(currentUsers.end()));
  }
  TC_RETURN(out);
}

auto UserAccessor::fetch(gsl::span<Trustchain::DeviceId const> deviceIds)
    -> tc::cotask<DevicesMap>
{
  if (deviceIds.empty())
    TC_RETURN(DevicesMap{});

  DevicesMap out;
  out.reserve(deviceIds.size());
  for (unsigned int i = 0; i < deviceIds.size(); i += ChunkSize)
  {
    auto const count = std::min<std::size_t>(ChunkSize, deviceIds.size() - i);
    auto const [trustchainCreation, actions] =
        TC_AWAIT(_requester->getUsers(deviceIds.subspan(i, count)));
    auto currentDevices =
        std::get<DevicesMap>(processUserEntries(_context, actions));
    out.insert(std::make_move_iterator(currentDevices.begin()),
               std::make_move_iterator(currentDevices.end()));
  }
  TC_RETURN(out);
}
}
