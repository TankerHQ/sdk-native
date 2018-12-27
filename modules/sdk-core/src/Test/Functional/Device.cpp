#include <Tanker/Test/Functional/Device.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include <fmt/core.h>
#include <tconcurrent/coroutine.hpp>

#include <string>
#include <utility>

namespace Tanker
{
namespace Test
{
static auto const STRONG_PASSWORD_DO_NOT_LEAK = Password("********");
#ifdef __linux__
// mount a tmpfs there and you will go 10s faster
static auto const TMP_PATH = "/tmp/tankertest";
#else
static auto const TMP_PATH = "tmptest";
#endif

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
               std::string userToken)
  : _trustchainUrl(std::move(trustchainUrl)),
    _trustchainId(std::move(trustchainId)),
    _suserId(std::move(suserId)),
    _userToken(std::move(userToken)),
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
      SdkInfo{"test", base64::decode<TrustchainId>(_trustchainId), "0.0.1"},
      _storage->path);
}

SUserId const& Device::suserId() const
{
  return this->_suserId;
}

std::string const& Device::userToken() const
{
  return this->_userToken;
}

tc::cotask<void> Device::attachDevice(AsyncCore& parentSession)
{
  assert(parentSession.status() == Status::Open);
  auto const core = TC_AWAIT(this->open(parentSession));
}

tc::cotask<void> Device::registerUnlock(AsyncCore& session)
{
  assert(session.status() == Status::Open);
  TC_AWAIT(session.registerUnlock(
      Unlock::RegistrationOptions{}.set(STRONG_PASSWORD_DO_NOT_LEAK)));
}

tc::cotask<AsyncCorePtr> Device::open(SessionType type)
{
  auto tanker = createCore(type);
  if (tanker->status() == Status::Open)
    TC_RETURN(std::move(tanker));

  auto const conn =
      tanker->connectEvent(Event::UnlockRequired, [&](void* param, void* data) {
        tc::async_resumable([&tanker]() -> tc::cotask<void> {
          try
          {
            TC_AWAIT(tanker->unlockCurrentDevice(STRONG_PASSWORD_DO_NOT_LEAK));
          }
          catch (std::exception const& e)
          {
            // TODO i'm sure we can do better than a cerr here
            fmt::print(stderr, "ERROR: can't unlock device: {:s}", e.what());
          }
        });
      });

  TC_AWAIT(tanker->open(_suserId, _userToken));
  if (tanker->status() != Status::Open)
    throw std::runtime_error("attach device fail");
  TC_RETURN(std::move(tanker));
}

tc::cotask<AsyncCorePtr> Device::open(AsyncCore& session)
{
  TC_AWAIT(registerUnlock(session));
  TC_RETURN(TC_AWAIT(open(SessionType::Cached)));
}
}
}
