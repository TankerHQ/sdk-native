#include <Tanker/Opener.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/ConnectionFactory.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Unlock/VerificationRequest.hpp>

#include <fmt/format.h>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/promise.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <memory>
#include <utility>

TLOG_CATEGORY(Core);

namespace Tanker
{
Opener::Opener(std::string url, SdkInfo info, std::string writablePath)
  : _url(std::move(url)),
    _info(std::move(info)),
    _writablePath(std::move(writablePath))
{
}

Status Opener::status() const
{
  return _status;
}

tc::cotask<Status> Opener::open(std::string const& b64Identity)
{
  SCOPE_TIMER("opener_open", Proc);
  if (_identity.has_value())
    throw Error::formatEx<Error::InvalidTankerStatus>(
        "start() has already been called");

  // FIXME: check for bad identity format
  _identity = Identity::extract<Identity::SecretPermanentIdentity>(b64Identity);

  if (_identity->trustchainId != _info.trustchainId)
    throw Error::formatEx<Error::InvalidArgument>(
        fmt("Identity's trustchain is {:s}, expected {:s}"),
        _identity->trustchainId,
        _info.trustchainId);

  _client = std::make_unique<Client>(ConnectionFactory::create(_url, _info));
  _client->start();

  std::string dbPath;
  if (_writablePath == ":memory:")
    dbPath = _writablePath;
  else
    dbPath = fmt::format(
        "{}/tanker-{:S}.db", _writablePath, _identity->delegation.userId);
  _db = TC_AWAIT(DataStore::createDatabase(dbPath, _identity->userSecret));
  _keyStore = TC_AWAIT(DeviceKeyStore::open(_db.get()));

  auto const userStatusResult =
      TC_AWAIT(_client->userStatus(_info.trustchainId,
                                   _identity->delegation.userId,
                                   _keyStore->signatureKeyPair().publicKey));
  if (userStatusResult.deviceExists)
    _status = Status::Ready;
  else if (userStatusResult.userExists)
    _status = Status::IdentityVerificationNeeded;
  else
    _status = Status::IdentityRegistrationNeeded;
  TC_RETURN(status());
}

tc::cotask<VerificationKey> Opener::fetchVerificationKey(
    Unlock::DeviceLocker const& locker)
{
  auto const req =
      Unlock::Request(_info.trustchainId, _identity->delegation.userId, locker);
  try
  {
    auto const fetchAnswer = TC_AWAIT(_client->fetchVerificationKey(req));
    TC_RETURN(fetchAnswer.getVerificationKey(_identity->userSecret));
  }
  catch (Error::ServerError const& err)
  {
    if (err.httpStatusCode() == 401)
    {
      if (mpark::holds_alternative<Password>(locker))
        throw Error::InvalidUnlockPassword{err.what()};
      else if (mpark::holds_alternative<VerificationCode>(locker))
        throw Error::InvalidVerificationCode{err.what()};
    }
    else if (err.httpStatusCode() == 404)
      throw Error::InvalidVerificationKey{err.what()};
    else if (err.httpStatusCode() == 429)
      throw Error::MaxVerificationAttemptsReached(err.what());
    throw;
  }
  throw std::runtime_error("unreachable code");
}

tc::cotask<void> Opener::unlockCurrentDevice(
    VerificationKey const& verificationKey)
{
  TINFO("unlockCurrentDevice");
  FUNC_TIMER(Proc);

  auto const ghostDevice = GhostDevice::create(verificationKey);
  // FIXME: Handle this error (invalid verification key)
  auto const encryptedUserKey = TC_AWAIT(_client->getLastUserKey(
      _info.trustchainId,
      Crypto::makeSignatureKeyPair(ghostDevice.privateSignatureKey).publicKey));

  auto const block = Unlock::createValidatedDevice(_info.trustchainId,
                                                   _identity->delegation.userId,
                                                   ghostDevice,
                                                   _keyStore->deviceKeys(),
                                                   encryptedUserKey);
  TC_AWAIT(_client->pushBlock(Serialization::serialize(block)));
}

Session::Config Opener::makeConfig()
{
  return {std::move(_db),
          _info.trustchainId,
          _identity->delegation.userId,
          _identity->userSecret,
          std::move(_keyStore),
          std::move(_client)};
}

tc::cotask<Session::Config> Opener::createUser(
    Unlock::Verification const& verification)
{
  TINFO("createUser");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityRegistrationNeeded)
    throw Error::formatEx<Error::InvalidTankerStatus>(
        "invalid status {}, should be {}",
        status(),
        Status::IdentityRegistrationNeeded);

  auto const verificationKey = mpark::get_if<VerificationKey>(&verification);
  auto const ghostDeviceKeys =
      verificationKey ? GhostDevice::create(*verificationKey).toDeviceKeys() :
                        DeviceKeys::create();
  auto const ghostDevice = GhostDevice::create(ghostDeviceKeys);

  auto const userCreation = Serialization::deserialize<Block>(
      BlockGenerator(_info.trustchainId, {}, {})
          .addUser(_identity->delegation,
                   ghostDeviceKeys.signatureKeyPair.publicKey,
                   ghostDeviceKeys.encryptionKeyPair.publicKey,
                   Crypto::makeEncryptionKeyPair()));
  auto const action =
      Serialization::deserialize<Trustchain::Actions::DeviceCreation::v3>(
          userCreation.payload);

  auto const firstDevice = Unlock::createValidatedDevice(
      _info.trustchainId,
      _identity->delegation.userId,
      ghostDevice,
      _keyStore->deviceKeys(),
      EncryptedUserKey{Trustchain::DeviceId{userCreation.hash()},
                       action.sealedPrivateUserEncryptionKey()});

  auto const encryptVerificationKey = Crypto::encryptAead(
      _identity->userSecret,
      gsl::make_span(Unlock::ghostDeviceToVerificationKey(ghostDevice))
          .as_span<uint8_t const>());

  TC_AWAIT(_client->createUser(
      *_identity,
      userCreation,
      firstDevice,
      makeVerificationRequest(verification, _identity->userSecret),
      encryptVerificationKey));
  TC_RETURN(makeConfig());
}

tc::cotask<VerificationKey> Opener::getVerificationKey(
    Unlock::Verification const& verification)
{
  if (auto const verificationKey =
          mpark::get_if<VerificationKey>(&verification))
    TC_RETURN(*verificationKey);
  else if (auto const emailVerification =
               mpark::get_if<Unlock::EmailVerification>(&verification))
    TC_RETURN(
        TC_AWAIT(fetchVerificationKey(emailVerification->verificationCode)));
  else if (auto const password = mpark::get_if<Password>(&verification))
    TC_RETURN(TC_AWAIT(fetchVerificationKey(*password)));
  throw std::runtime_error(
      "assertion error: invalid Verification, unreachable code");
}

tc::cotask<Session::Config> Opener::createDevice(
    Unlock::Verification const& verification)
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityVerificationNeeded)
    throw Error::formatEx<Error::InvalidTankerStatus>(
        "invalid status {}, should be {}",
        status(),
        Status::IdentityVerificationNeeded);

  auto const verificationKey = TC_AWAIT(getVerificationKey(verification));
  TC_AWAIT(unlockCurrentDevice(verificationKey));
  TC_RETURN(makeConfig());
}

tc::cotask<Session::Config> Opener::openDevice()
{
  TINFO("openDevice");
  if (status() != Status::Ready)
    throw Error::formatEx<Error::InvalidTankerStatus>(
        "invalid status {}, should be {}", status(), Status::Ready);
  TC_RETURN(makeConfig());
}
}
