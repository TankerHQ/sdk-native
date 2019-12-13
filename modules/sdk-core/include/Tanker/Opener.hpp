#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>

#include <cstdint>
#include <memory>
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

private:
  std::string _url;
  Network::SdkInfo _info;
  std::string _writablePath;

  std::optional<Identity::SecretPermanentIdentity> _identity;
  DataStore::DatabasePtr _db;
  Users::LocalUser::Ptr _localUser;
  std::unique_ptr<Client> _client;
  std::unique_ptr<Users::Requester> _userRequester;
  Trustchain::UserId _userId;

  tc::cotask<void> unlockCurrentDevice(VerificationKey const& verificationKey);
  Status _status = Status::Stopped;

  tc::cotask<VerificationKey> getVerificationKey(Unlock::Verification const&);
  Session::Config makeConfig();
};
}
