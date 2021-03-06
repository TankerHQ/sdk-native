#include <Tanker/Functional/Device.hpp>

#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <mgs/base64.hpp>
#include <tconcurrent/coroutine.hpp>

#include <string>
#include <utility>

namespace Tanker
{
namespace Functional
{
Passphrase const Device::STRONG_PASSWORD_DO_NOT_LEAK = Passphrase("********");
static auto const TMP_PATH = "testtmp";

Device::Device(std::string trustchainUrl,
               std::string trustchainId,
               std::string identity)
  : _trustchainUrl(std::move(trustchainUrl)),
    _trustchainId(std::move(trustchainId)),
    _identity(std::move(identity)),
    _storage(std::make_shared<UniquePath>(TMP_PATH))
{
}

AsyncCorePtr Device::createCore(SessionType type)
{
  if (type == SessionType::New)
    return AsyncCorePtr(createAsyncCore().release(), AsyncCoreDeleter{});

  if (!*_cachedSession)
    *_cachedSession =
        AsyncCorePtr(createAsyncCore().release(), AsyncCoreDeleter{});

  return *_cachedSession;
}

std::unique_ptr<AsyncCore> Device::createAsyncCore()
{
  return std::make_unique<AsyncCore>(
      _trustchainUrl, getSdkInfo(), _storage->path);
}

SdkInfo Device::getSdkInfo()
{
  return SdkInfo{
      "sdk-native-test",
      mgs::base64::decode<Tanker::Trustchain::TrustchainId>(_trustchainId),
      "0.0.1"};
}

std::string const& Device::identity() const
{
  return this->_identity;
}

std::string Device::writablePath() const
{
  return _storage->path;
}

tc::cotask<AsyncCorePtr> Device::open(SessionType sessionType)
{
  auto tanker = createCore(sessionType);
  if (tanker->status() == Status::Ready)
    TC_RETURN(std::move(tanker));

  auto const status = TC_AWAIT(tanker->start(_identity));
  if (status == Status::IdentityRegistrationNeeded)
    TC_AWAIT(tanker->registerIdentity(
        Unlock::Verification{STRONG_PASSWORD_DO_NOT_LEAK}));
  else if (status == Status::IdentityVerificationNeeded)
    TC_AWAIT(tanker->verifyIdentity(
        Unlock::Verification{STRONG_PASSWORD_DO_NOT_LEAK}));
  TC_RETURN(std::move(tanker));
}
}
}
