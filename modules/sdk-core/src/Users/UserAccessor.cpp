#include <Tanker/Users/UserAccessor.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Users/Updater.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(UserAccessor);

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

auto UserAccessor::pull(gsl::span<UserId const> userIds)
    -> tc::cotask<PullResult>
{
  auto const userIdsMap = TC_AWAIT(fetch(userIds));

  PullResult ret;
  ret.found.reserve(userIds.size());

  for (auto const& userId : userIds)
    if (auto it = userIdsMap.find(userId); it != userIdsMap.end())
      ret.found.push_back(it->second);
    else
      ret.notFound.push_back(userId);

  TC_RETURN(ret);
}

tc::cotask<BasicPullResult<Device, Trustchain::DeviceId>> UserAccessor::pull(
    gsl::span<Trustchain::DeviceId const> deviceIds)
{
  auto const deviceIdsMap = TC_AWAIT(fetch(deviceIds));

  BasicPullResult<Device, Trustchain::DeviceId> ret;
  ret.found.reserve(deviceIds.size());

  for (auto const& deviceId : deviceIds)
    if (auto it = deviceIdsMap.find(deviceId); it != deviceIdsMap.end())
      ret.found.push_back(it->second);
    else
      ret.notFound.push_back(deviceId);

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
                        gsl::span<Trustchain::UserAction const> serverEntries)
{
  UsersMap usersMap;
  DevicesMap devicesMap;
  for (auto const& serverEntry : serverEntries)
  {
    if (auto const dc = boost::variant2::get_if<DeviceCreation>(&serverEntry))
    {
      std::optional<Users::User> user;
      auto const userIt = usersMap.find(dc->userId());

      if (userIt != usersMap.end())
        user = userIt->second;

      auto const entry = Verif::verifyDeviceCreation(*dc, context, user);

      user = Updater::applyDeviceCreationToUser(entry, user);
      usersMap[dc->userId()] = *user;
      auto const& lastDevice = user->devices().back();
      if (auto const [it, isInserted] =
              devicesMap.emplace(lastDevice.id(), lastDevice);
          isInserted == false)
        throw Errors::AssertionError("DeviceCreation received more than once");
    }
    else if (auto const deviceRevocation =
                 boost::variant2::get_if<DeviceRevocation>(&serverEntry))
    {
      auto const user =
          findUserOfDevice(devicesMap, usersMap, deviceRevocation->deviceId());
      auto const entry = Verif::verifyDeviceRevocation(
          *deviceRevocation, user ? std::make_optional(*user) : std::nullopt);
      if (!user)
        throw Errors::AssertionError(
            "user not found, verification should have failed");

      *user = Updater::applyDeviceRevocationToUser(entry, *user);
    }
    else
    {
      TERROR("Expected user blocks but got {}",
             Trustchain::getNature(serverEntry));
    }
  }
  return std::make_tuple(usersMap, devicesMap);
}
}

tc::cotask<std::vector<ProvisionalUsers::PublicUser>>
UserAccessor::pullProvisional(
    gsl::span<Identity::PublicProvisionalIdentity const>
        appProvisionalIdentities)
{
  if (appProvisionalIdentities.empty())
    TC_RETURN(std::vector<ProvisionalUsers::PublicUser>{});

  std::vector<Email> provisionalUserEmails;
  for (auto const& appProvisionalIdentity : appProvisionalIdentities)
  {
    if (appProvisionalIdentity.target != Identity::TargetType::Email)
    {
      throw AssertionError(
          fmt::format("unsupported target type: {}",
                      static_cast<int>(appProvisionalIdentity.target)));
    }
    provisionalUserEmails.push_back(Email{appProvisionalIdentity.value});
  }

  auto const tankerProvisionalIdentities = TC_AWAIT(
      _requester->getPublicProvisionalIdentities(provisionalUserEmails));

  if (appProvisionalIdentities.size() != tankerProvisionalIdentities.size())
  {
    throw formatEx(
        Errc::InternalError,
        "getPublicProvisionalIdentities returned a list of different size");
  }

  std::vector<ProvisionalUsers::PublicUser> provisionalUsers;
  provisionalUsers.reserve(appProvisionalIdentities.size());
  std::transform(appProvisionalIdentities.begin(),
                 appProvisionalIdentities.end(),
                 tankerProvisionalIdentities.begin(),
                 std::back_inserter(provisionalUsers),
                 [](auto const& appProvisionalIdentity,
                    auto const& tankerProvisionalIdentity) {
                   auto const& [sigKey, encKey] = tankerProvisionalIdentity;
                   return ProvisionalUsers::PublicUser{
                       appProvisionalIdentity.appSignaturePublicKey,
                       appProvisionalIdentity.appEncryptionPublicKey,
                       sigKey,
                       encKey,
                   };
                 });

  TC_RETURN(provisionalUsers);
}

auto UserAccessor::fetch(gsl::span<Trustchain::UserId const> userIds)
    -> tc::cotask<UsersMap>
{
  if (userIds.empty())
    TC_RETURN(UsersMap{});
  auto const serverEntries = TC_AWAIT(_requester->getUsers(userIds));
  TC_RETURN(std::get<UsersMap>(processUserEntries(_context, serverEntries)));
}

auto UserAccessor::fetch(gsl::span<Trustchain::DeviceId const> deviceIds)
    -> tc::cotask<DevicesMap>
{
  if (deviceIds.empty())
    TC_RETURN(DevicesMap{});
  auto const serverEntries = TC_AWAIT(_requester->getUsers(deviceIds));
  TC_RETURN(std::get<DevicesMap>(processUserEntries(_context, serverEntries)));
}
}
