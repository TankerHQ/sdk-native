#include <Tanker/Opener.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/ConnectionFactory.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/EnumFormat.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/UserToken/Delegation.hpp>
#include <Tanker/UserToken/UserToken.hpp>

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

Status Opener::status() const
{
  return _status;
}

tc::cotask<Session::Config> Opener::open(SUserId const& suserId,
                                         std::string const& b64UserToken)
{
  SCOPE_TIMER("opener_open", Proc);
  auto const userToken = UserToken::extract(b64UserToken);

  _userId = userToken.delegation.userId;
  _userSecret = userToken.userSecret;
  if (obfuscateUserId(suserId, _info.trustchainId) != _userId)
    throw Error::formatEx<Error::InvalidArgument>(
        fmt("User id mismatch. Provided: {:s}, inside user_token: {:s}"),
        suserId,
        _userId.value());

  _client = std::make_unique<Client>(ConnectionFactory::create(_url, _info));
  _client->start();

  _db = TC_AWAIT(DataStore::createDatabase(
      fmt::format("{}/tanker-{:S}.db", _writablePath, *_userId), _userSecret));
  _keyStore = TC_AWAIT(DeviceKeyStore::open(_db.get()));

  auto const userStatusResult =
      TC_AWAIT(_client->userStatus(_info.trustchainId,
                                   _userId.value(),
                                   _keyStore->signatureKeyPair().publicKey));
  if (userStatusResult.deviceExists)
    TC_AWAIT(openDevice());
  else if (userStatusResult.userExists)
  {
    _status = Status::DeviceCreation;
    TC_AWAIT(createDevice());
  }
  else
  {
    _status = Status::UserCreation;
    TC_AWAIT(createUser(userToken));
  }

  _status = Status::Closed;
  TC_RETURN(makeConfig(userToken.userSecret));
}

tc::cotask<void> Opener::connectionHandler()
{
  try
  {
    auto const skp = _keyStore->signatureKeyPair();
    TC_AWAIT(_client->subscribeToCreation(
        _info.trustchainId,
        skp.publicKey,
        Crypto::sign(skp.publicKey, skp.privateKey)));
  }
  catch (std::exception const& e)
  {
    TERROR("Failed to subscribe to device creation {}", e.what());
  }
}

tc::cotask<UnlockKey> Opener::fetchUnlockKey(Unlock::DeviceLocker const& locker)
{
  auto const req = Unlock::Request(_info.trustchainId, _userId.value(), locker);
  try
  {
    auto const fetchAnswer = TC_AWAIT(_client->fetchUnlockKey(req));
    TC_RETURN(fetchAnswer.getUnlockKey(_userSecret.value()));
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

tc::future<void> Opener::waitForUnlock()
{
  tc::promise<void> prom;
  auto fut = prom.get_future();
  auto const conn = std::make_shared<boost::signals2::connection>();
  *conn =
      _client->deviceCreated.connect([prom = std::move(prom), conn]() mutable {
        prom.set_value({});
        conn->disconnect();
      });
  return fut;
}

tc::cotask<void> Opener::unlockCurrentDevice(UnlockKey const& unlockKey)
{
  if (_status != Status::DeviceCreation)
    throw Error::formatEx<Error::InvalidTankerStatus>(
        fmt("invalid status {:e} for validatedCurrentDevice"),
        static_cast<Status>(_status));
  auto const ghostDevice = Unlock::extract(unlockKey);

  auto const encryptedUserKey = TC_AWAIT(
      _client->getLastUserKey(_info.trustchainId, ghostDevice.deviceId));

  auto const block = Unlock::createValidatedDevice(_info.trustchainId,
                                                   *_userId,
                                                   ghostDevice,
                                                   _keyStore->deviceKeys(),
                                                   encryptedUserKey);
  TC_AWAIT(_client->pushBlock(block));
}

Session::Config Opener::makeConfig(Crypto::SymmetricKey const& userSecret)
{
  return {std::move(_db),
          _info.trustchainId,
          _userId.value(),
          userSecret,
          std::move(_keyStore),
          std::move(_client)};
}

tc::cotask<void> Opener::createUser(UserToken::UserToken const& userToken)
{
  TINFO("createUser");
  FUNC_TIMER(Proc);

  auto const block =
      BlockGenerator(
          _info.trustchainId, _keyStore->signatureKeyPair().privateKey, {})
          .addUser(userToken.delegation,
                   _keyStore->signatureKeyPair().publicKey,
                   _keyStore->encryptionKeyPair().publicKey,
                   Crypto::makeEncryptionKeyPair());

  TC_AWAIT(_client->pushBlock(block));
}

tc::cotask<void> Opener::createDevice()
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);

  unlockRequired();

  auto fut = waitForUnlock();
  _client->setConnectionHandler(
      [this]() -> tc::cotask<void> { TC_AWAIT(connectionHandler()); });
  TC_AWAIT(_client->handleConnection());
  TC_AWAIT(std::move(fut));
}

tc::cotask<void> Opener::openDevice()
{
  TINFO("openDevice");
  TC_RETURN();
}
}
