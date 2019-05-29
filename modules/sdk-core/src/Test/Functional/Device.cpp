#include <Tanker/Test/Functional/Device.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/core.h>
#include <tconcurrent/coroutine.hpp>

#include <string>
#include <utility>

namespace Tanker
{
namespace Test
{
static auto const STRONG_PASSWORD_DO_NOT_LEAK = Password("********");
static auto const TMP_PATH = "testtmp";

namespace
{
struct AsyncCoreDeleter
{
  void operator()(AsyncCore* core) const
  {
    core->destroy().get();
  }
};
}

Device::Device(std::string trustchainUrl,
               std::string trustchainId,
               SUserId suserId,
               std::string identity)
  : _trustchainUrl(std::move(trustchainUrl)),
    _trustchainId(std::move(trustchainId)),
    _suserId(std::move(suserId)),
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
      _trustchainUrl,
      SdkInfo{"test",
              cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
                  _trustchainId),
              "0.0.1"},
      _storage->path);
}

SUserId const& Device::suserId() const
{
  return this->_suserId;
}

std::string const& Device::identity() const
{
  return this->_identity;
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
