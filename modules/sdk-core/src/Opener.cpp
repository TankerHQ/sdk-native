#include <Tanker/Opener.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Network/ConnectionFactory.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/promise.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <memory>
#include <utility>

using namespace Tanker::Errors;

TLOG_CATEGORY(Core);

namespace Tanker
{
Opener::Opener(std::string url, Network::SdkInfo info, std::string writablePath)
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
  {
    throw Exception(make_error_code(Errc::PreconditionFailed),
                    "start() has already been called");
  }

  _identity = Identity::extract<Identity::SecretPermanentIdentity>(b64Identity);

  if (_identity->trustchainId != _info.trustchainId)
  {
    throw formatEx(Errc::InvalidArgument,
                   TFMT("identity's trustchain is {:s}, expected {:s}"),
                   _identity->trustchainId,
                   _info.trustchainId);
  }

  _client =
      std::make_unique<Client>(Network::ConnectionFactory::create(_url, _info));
  _client->start();

  std::string dbPath;
  if (_writablePath == ":memory:")
    dbPath = _writablePath;
  else
    dbPath = fmt::format(TFMT("{:s}/tanker-{:S}.db"),
                         _writablePath,
                         _identity->delegation.userId);
  _db = TC_AWAIT(DataStore::createDatabase(dbPath, _identity->userSecret));
  _localUser = TC_AWAIT(Users::LocalUser::open(_identity.value(), _db.get()));

  auto const userStatusResult = TC_AWAIT(
      _client->userStatus(_info.trustchainId,
                          _localUser->userId(),
                          _localUser->deviceKeys().signatureKeyPair.publicKey));

  if (userStatusResult.deviceExists)
    _status = Status::Ready;
  else if (userStatusResult.userExists)
    _status = Status::IdentityVerificationNeeded;
  else
    _status = Status::IdentityRegistrationNeeded;
  TC_RETURN(status());
}

tc::cotask<VerificationKey> Opener::fetchVerificationKey(
    Unlock::Verification const& verification)
{
  TC_RETURN(TC_AWAIT(_client->fetchVerificationKey(_info.trustchainId,
                                                   _identity->delegation.userId,
                                                   verification,
                                                   _identity->userSecret)));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Opener::fetchVerificationMethods()
{
  TC_RETURN(
      TC_AWAIT(_client->fetchVerificationMethods(_info.trustchainId,
                                                 _identity->delegation.userId,
                                                 _identity->userSecret)));
}

tc::cotask<void> Opener::unlockCurrentDevice(
    VerificationKey const& verificationKey)
{
  TINFO("unlockCurrentDevice");
  FUNC_TIMER(Proc);

  try
  {
    auto const ghostDeviceKeys =
        GhostDevice::create(verificationKey).toDeviceKeys();
    auto const encryptedUserKey = TC_AWAIT(_client->getLastUserKey(
        _info.trustchainId, ghostDeviceKeys.signatureKeyPair.publicKey));
    auto const privateUserEncryptionKey =
        Crypto::sealDecrypt(encryptedUserKey.encryptedPrivateKey,
                            ghostDeviceKeys.encryptionKeyPair);
    auto const entry = Users::createNewDeviceEntry(
        _info.trustchainId,
        encryptedUserKey.deviceId,
        Identity::makeDelegation(_identity->delegation.userId,
                                 ghostDeviceKeys.signatureKeyPair.privateKey),
        _localUser->deviceKeys().signatureKeyPair.publicKey,
        _localUser->deviceKeys().encryptionKeyPair.publicKey,
        Crypto::makeEncryptionKeyPair(privateUserEncryptionKey));
    TC_AWAIT(_client->pushBlock(Serialization::serialize(entry)));
  }
  catch (Exception const& e)
  {
    if (e.errorCode() == ServerErrc::DeviceNotFound ||
        e.errorCode() == Errc::DecryptionFailed)
      throw Exception(make_error_code(Errc::InvalidVerification), e.what());
    throw;
  }
}

Session::Config Opener::makeConfig()
{
  return {std::move(_db),
          _info.trustchainId,
          std::move(_localUser),
          std::move(_client)};
}

tc::cotask<Session::Config> Opener::createUser(
    Unlock::Verification const& verification)
{
  TINFO("createUser");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityRegistrationNeeded)
  {
    throw formatEx(Errc::PreconditionFailed,
                   TFMT("invalid status {:e}, should be {:e}"),
                   status(),
                   Status::IdentityRegistrationNeeded);
  }

  auto const verificationKey =
      boost::variant2::get_if<VerificationKey>(&verification);
  auto const ghostDeviceKeys =
      verificationKey ? GhostDevice::create(*verificationKey).toDeviceKeys() :
                        DeviceKeys::create();
  auto const ghostDevice = GhostDevice::create(ghostDeviceKeys);

  auto const userKeyPair = Crypto::makeEncryptionKeyPair();
  auto const userCreationEntry =
      Users::createNewUserEntry(_info.trustchainId,
                                _identity->delegation,
                                ghostDeviceKeys.signatureKeyPair.publicKey,
                                ghostDeviceKeys.encryptionKeyPair.publicKey,
                                userKeyPair);

  auto const firstDeviceEntry = Users::createNewDeviceEntry(
      _info.trustchainId,
      Trustchain::DeviceId{userCreationEntry.hash()},
      Identity::makeDelegation(_identity->delegation.userId,
                               ghostDevice.privateSignatureKey),
      _localUser->deviceKeys().signatureKeyPair.publicKey,
      _localUser->deviceKeys().encryptionKeyPair.publicKey,
      userKeyPair);

  auto const encryptVerificationKey = Crypto::encryptAead(
      _identity->userSecret,
      gsl::make_span(ghostDevice.toVerificationKey()).as_span<uint8_t const>());

  TC_AWAIT(_client->createUser(*_identity,
                               Serialization::serialize(userCreationEntry),
                               Serialization::serialize(firstDeviceEntry),
                               verification,
                               _identity->userSecret,
                               encryptVerificationKey));
  TC_RETURN(makeConfig());
}

tc::cotask<VerificationKey> Opener::getVerificationKey(
    Unlock::Verification const& verification)
{
  using boost::variant2::get_if;
  using boost::variant2::holds_alternative;

  if (auto const verificationKey = get_if<VerificationKey>(&verification))
    TC_RETURN(*verificationKey);
  else if (holds_alternative<Unlock::EmailVerification>(verification) ||
           holds_alternative<Passphrase>(verification) ||
           holds_alternative<OidcIdToken>(verification))
    TC_RETURN(TC_AWAIT(fetchVerificationKey(verification)));
  throw AssertionError("invalid verification, unreachable code");
}

tc::cotask<VerificationKey> Opener::generateVerificationKey() const
{
  TC_RETURN(GhostDevice::create().toVerificationKey());
}

tc::cotask<Session::Config> Opener::createDevice(
    Unlock::Verification const& verification)
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityVerificationNeeded)
  {
    throw formatEx(Errc::PreconditionFailed,
                   TFMT("invalid status {:e}, should be {:e}"),
                   status(),
                   Status::IdentityVerificationNeeded);
  }

  auto const verificationKey = TC_AWAIT(getVerificationKey(verification));
  TC_AWAIT(unlockCurrentDevice(verificationKey));
  TC_RETURN(makeConfig());
}

tc::cotask<Session::Config> Opener::openDevice()
{
  TINFO("openDevice");
  if (status() != Status::Ready)
  {
    throw formatEx(Errc::PreconditionFailed,
                   TFMT("invalid status {:e}, should be {:e}"),
                   status(),
                   Status::Ready);
  }
  TC_RETURN(makeConfig());
}
}
