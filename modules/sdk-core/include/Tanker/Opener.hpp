#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Identity/Identity.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>

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
class DeviceKeyStore;

enum class OpenMode
{
  SignUp,
  SignIn,
};

struct SignInOptions
{
  nonstd::optional<UnlockKey> unlockKey;
  nonstd::optional<VerificationCode> verificationCode;
  nonstd::optional<Password> password;
};

class Opener
{
public:
  struct StatusIdentityNotRegistered
  {
  };
  struct StatusIdentityVerificationNeeded
  {
  };

  using OpenResult = mpark::variant<Session::Config,
                                    StatusIdentityNotRegistered,
                                    StatusIdentityVerificationNeeded>;

  Opener(std::string url, SdkInfo info, std::string writablePath);

  Status status() const;

  tc::cotask<OpenResult> open(std::string const& b64Identity,
                              SignInOptions const& signInOptions,
                              OpenMode mode);

  tc::cotask<UnlockKey> fetchUnlockKey(Unlock::DeviceLocker const& pass);
  tc::cotask<void> unlockCurrentDevice(UnlockKey const& unlockKey);

  boost::signals2::signal<void()> unlockRequired;

private:
  std::string _url;
  SdkInfo _info;
  std::string _writablePath;

  nonstd::optional<Identity::Identity> _identity;
  DataStore::DatabasePtr _db;
  std::unique_ptr<DeviceKeyStore> _keyStore;
  std::unique_ptr<Client> _client;

  Status _status = Status::Closed;

  Session::Config makeConfig();
  tc::cotask<OpenResult> createUser();
  tc::cotask<OpenResult> createDevice(SignInOptions const& signInOptions);
  tc::cotask<OpenResult> openDevice();
};
}
