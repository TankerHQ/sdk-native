#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>
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

struct EmailVerification
{
  Email email;
  VerificationCode verificationCode;
};

struct Verification
{
  nonstd::optional<VerificationKey> verificationKey;
  nonstd::optional<EmailVerification> emailVerification;
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
                              Verification const& verification,
                              OpenMode mode);

  tc::cotask<VerificationKey> fetchVerificationKey(
      Unlock::DeviceLocker const& pass);

private:
  std::string _url;
  SdkInfo _info;
  std::string _writablePath;

  nonstd::optional<Identity::SecretPermanentIdentity> _identity;
  DataStore::DatabasePtr _db;
  std::unique_ptr<DeviceKeyStore> _keyStore;
  std::unique_ptr<Client> _client;

  tc::cotask<void> unlockCurrentDevice(VerificationKey const& verificationKey);
  Status _status = Status::Stopped;

  Session::Config makeConfig();
  tc::cotask<OpenResult> createUser();
  tc::cotask<OpenResult> createDevice(Verification const& verification);
  tc::cotask<OpenResult> openDevice();
};
}
