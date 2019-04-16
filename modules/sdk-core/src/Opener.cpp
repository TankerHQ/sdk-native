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
#include <Tanker/Session.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>

#include <boost/signals2/connection.hpp>
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

tc::cotask<Opener::OpenResult> Opener::open(std::string const& b64Identity,
                                            SignInOptions const& signInOptions,
                                            OpenMode mode)
{
  SCOPE_TIMER("opener_signup", Proc);
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
  if (userStatusResult.userExists && mode == OpenMode::SignUp)
    throw Error::IdentityAlreadyRegistered(
        "signUp failed: user already exists");
  if (userStatusResult.deviceExists)
    TC_RETURN(TC_AWAIT(openDevice()));
  else if (userStatusResult.userExists)
    TC_RETURN(TC_AWAIT(createDevice(signInOptions)));
  else if (mode == OpenMode::SignUp)
    TC_RETURN(TC_AWAIT(createUser()));
  else if (mode == OpenMode::SignIn)
    TC_RETURN(StatusIdentityNotRegistered{});
  throw std::runtime_error(
      "assertion error: invalid open mode, unreachable code");
}

tc::cotask<UnlockKey> Opener::fetchUnlockKey(Unlock::DeviceLocker const& locker)
{
  auto const req =
      Unlock::Request(_info.trustchainId, _identity->delegation.userId, locker);
  try
  {
    auto const fetchAnswer = TC_AWAIT(_client->fetchUnlockKey(req));
    TC_RETURN(fetchAnswer.getUnlockKey(_identity->userSecret));
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
      throw Error::InvalidUnlockKey{err.what()};
    else if (err.httpStatusCode() == 429)
      throw Error::MaxVerificationAttemptsReached(err.what());
    throw;
  }
  throw std::runtime_error("unreachable code");
}

tc::cotask<void> Opener::unlockCurrentDevice(UnlockKey const& unlockKey)
{
  auto const ghostDevice = Unlock::extract(unlockKey);

  auto const encryptedUserKey = TC_AWAIT(
      _client->getLastUserKey(_info.trustchainId, ghostDevice.deviceId));

  auto const block = Unlock::createValidatedDevice(_info.trustchainId,
                                                   _identity->delegation.userId,
                                                   ghostDevice,
                                                   _keyStore->deviceKeys(),
                                                   encryptedUserKey);
  TC_AWAIT(_client->pushBlock(block));
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

tc::cotask<Opener::OpenResult> Opener::createUser()
{
  TINFO("createUser");
  FUNC_TIMER(Proc);

  auto const block =
      BlockGenerator(
          _info.trustchainId, _keyStore->signatureKeyPair().privateKey, {})
          .addUser(_identity->delegation,
                   _keyStore->signatureKeyPair().publicKey,
                   _keyStore->encryptionKeyPair().publicKey,
                   Crypto::makeEncryptionKeyPair());

  TC_AWAIT(_client->pushBlock(block));
  TC_RETURN(makeConfig());
}

tc::cotask<Opener::OpenResult> Opener::createDevice(
    SignInOptions const& signInOptions)
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);

  if (signInOptions.unlockKey)
    TC_AWAIT(unlockCurrentDevice(*signInOptions.unlockKey));
  else if (signInOptions.verificationCode)
    TC_AWAIT(unlockCurrentDevice(
        TC_AWAIT(fetchUnlockKey(*signInOptions.verificationCode))));
  else if (signInOptions.password)
    TC_AWAIT(
        unlockCurrentDevice(TC_AWAIT(fetchUnlockKey(*signInOptions.password))));
  else
    TC_RETURN(StatusIdentityVerificationNeeded{});

  TC_RETURN(makeConfig());
}

tc::cotask<Opener::OpenResult> Opener::openDevice()
{
  TINFO("openDevice");
  TC_RETURN(makeConfig());
}
}
