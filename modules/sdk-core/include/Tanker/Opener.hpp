#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserStore.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Tanker::Users
{
class Requester;
}

namespace Tanker
{
class Opener
{
public:
  Opener(std::string url, Network::SdkInfo info, std::string writablePath);
  ~Opener();

  Status status() const;

  tc::cotask<Status> open(std::string const& b64Identity);
  tc::cotask<Session::Config> openDevice();
  tc::cotask<Session::Config> createUser(
      Unlock::Verification const& verification);
  tc::cotask<Session::Config> createDevice(
      Unlock::Verification const& verification);
  tc::cotask<VerificationKey> generateVerificationKey() const;

  tc::cotask<VerificationKey> fetchVerificationKey(
      Unlock::Verification const& verification);
  tc::cotask<std::vector<Unlock::VerificationMethod>>
  fetchVerificationMethods();

  tc::cotask<void> nukeDatabase();

private:
  std::string _url;
  Network::SdkInfo _info;
  std::string _writablePath;

  std::optional<Identity::SecretPermanentIdentity> _identity;
  Trustchain::Context _trustchainContext;
  std::optional<DeviceKeys> _deviceKeys;
  DataStore::DatabasePtr _db;
  std::unique_ptr<Users::LocalUserStore> _localUserStore;
  std::unique_ptr<Users::LocalUserAccessor> _localUserAccessor;
  std::unique_ptr<Users::ContactStore> _contactStore;
  std::unique_ptr<Client> _client;
  std::unique_ptr<Users::Requester> _userRequester;
  Status _status = Status::Stopped;

  tc::cotask<void> unlockCurrentDevice(VerificationKey const& verificationKey);
  tc::cotask<void> fetchUser();
  void extractIdentity(std::string const& b64Identity);

  tc::cotask<VerificationKey> getVerificationKey(Unlock::Verification const&);
  Session::Config makeConfig();
};
}
