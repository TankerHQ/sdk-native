#include <Tanker/Test/Functional/Device.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>
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

tc::cotask<void> Device::attachDevice(AsyncCore& parentSession)
{
  assert(parentSession.status() == Status::Ready);
  auto const core = TC_AWAIT(this->open(parentSession));
}

tc::cotask<void> Device::registerUnlock(AsyncCore& session)
{
  assert(session.status() == Status::Ready);
  TC_AWAIT(session.registerUnlock(
      Unlock::RegistrationOptions{}.set(STRONG_PASSWORD_DO_NOT_LEAK)));
}

tc::cotask<AsyncCorePtr> Device::open(SessionType type)
{
  auto tanker = createCore(type);
  if (tanker->status() == Status::Ready)
    TC_RETURN(std::move(tanker));

  auto const openResult = TC_AWAIT(tanker->signIn(_identity));
  if (openResult == OpenResult::IdentityNotRegistered)
    TC_AWAIT(tanker->signUp(_identity));
  else if (openResult == OpenResult::IdentityVerificationNeeded)
  {
    auto const openResult2 =
        TC_AWAIT(tanker->signIn(_identity,
                                SignInOptions{
                                    nonstd::nullopt,
                                    nonstd::nullopt,
                                    STRONG_PASSWORD_DO_NOT_LEAK,
                                }));
    if (openResult2 != OpenResult::Ok)
      throw std::runtime_error("could not open functional test session");
  }
  TC_RETURN(std::move(tanker));
}

tc::cotask<AsyncCorePtr> Device::open(AsyncCore& session)
{
  TC_AWAIT(registerUnlock(session));
  TC_RETURN(TC_AWAIT(open(SessionType::Cached)));
}
}
}
