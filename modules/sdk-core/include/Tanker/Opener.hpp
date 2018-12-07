#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>

#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
namespace UserToken
{
struct UserToken;
}

class DeviceKeyStore;

class Opener
{
public:
  Opener(TrustchainId const& trustchainId,
         std::string const& trustchainUrl,
         boost::filesystem::path const& writablePath);

  Status status() const;

  tc::cotask<Session::Config> open(SUserId const& suserId,
                                   std::string const& userToken);

  tc::cotask<UnlockKey> fetchUnlockKey(Unlock::DeviceLocker const& pass);

  tc::cotask<void> unlockCurrentDevice(UnlockKey const& unlockKey);

  boost::signals2::signal<void()> unlockRequired;

private:
  TrustchainId const _trustchainId;
  std::string _trustchainUrl;
  boost::filesystem::path _writablePath;

  nonstd::optional<UserId> _userId;
  nonstd::optional<Crypto::SymmetricKey> _userSecret;
  DataStore::DatabasePtr _db;
  std::unique_ptr<DeviceKeyStore> _keyStore;
  std::unique_ptr<Client> _client;

  Status _status = Status::Closed;

  Session::Config makeConfig(Crypto::SymmetricKey const& userSecret);
  tc::cotask<void> createUser(UserToken::UserToken const& userToken);
  tc::cotask<void> createDevice();
  tc::cotask<void> openDevice();
  tc::future<void> waitForUnlock();
  tc::cotask<void> connectionHandler();
};
}
