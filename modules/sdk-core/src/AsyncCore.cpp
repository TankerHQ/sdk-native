#include <Tanker/AsyncCore.hpp>

#include <Tanker/Core.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Version.hpp>

#include <fmt/format.h>
#include <tconcurrent/async.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <memory>
#include <string>
#include <utility>

TLOG_CATEGORY(sdk);

namespace Tanker
{
AsyncCore::AsyncCore(std::string url, SdkInfo info, std::string writablePath)
  : _core(std::make_unique<Core>(
        std::move(url), std::move(info), std::move(writablePath)))
{
}

AsyncCore::~AsyncCore() = default;

tc::future<void> AsyncCore::destroy()
{
  if (tc::get_default_executor().is_in_this_context())
    return tc::sync([&] { delete this; });
  else
    return tc::async([&] { delete this; });
}

expected<boost::signals2::scoped_connection> AsyncCore::connectEvent(
    Event event, std::function<void(void*, void*)> cb, void* data)
{
  return tc::sync([=] {
    return boost::signals2::scoped_connection([=] {
      switch (event)
      {
      case Event::DeviceCreated:
        return this->_core->deviceCreated.connect(
            [cb, data] { tc::async([=] { cb(nullptr, data); }); });
      case Event::SessionClosed:
        return this->_core->sessionClosed.connect(
            [cb, data] { tc::async([=] { cb(nullptr, data); }); });
      case Event::DeviceRevoked:
        return this->_core->deviceRevoked.connect(
            [cb, data]() { tc::async([=] { cb(nullptr, data); }); });
      default:
        throw Error::formatEx<Error::InvalidArgument>(fmt("unknown event {:d}"),
                                                      static_cast<int>(event));
      }
    }());
  });
}

expected<void> AsyncCore::disconnectEvent(
    boost::signals2::scoped_connection conn)
{
  return tc::make_ready_future();
}

tc::future<void> AsyncCore::signUp(std::string const& identity,
                                   AuthenticationMethods const& authMethods)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->signUp(identity, authMethods));
  });
}

tc::future<OpenResult> AsyncCore::signIn(std::string const& identity,
                                         SignInOptions const& signInOptions)
{
  return tc::async_resumable([=]() -> tc::cotask<OpenResult> {
    TC_RETURN(TC_AWAIT(this->_core->signIn(identity, signInOptions)));
  });
}

tc::future<void> AsyncCore::signOut()
{
  return tc::async([this] { this->_core->signOut(); });
}

bool AsyncCore::isOpen() const
{
  return this->_core->isOpen();
}

tc::future<void> AsyncCore::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->encrypt(
        encryptedData, clearData, publicIdentities, groupIds));
  });
}

tc::future<void> AsyncCore::decrypt(uint8_t* decryptedData,
                                    gsl::span<uint8_t const> encryptedData)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->decrypt(decryptedData, encryptedData));
  });
}

tc::future<void> AsyncCore::share(
    std::vector<SResourceId> const& resourceId,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->share(resourceId, publicIdentities, groupIds));
  });
}

tc::future<SGroupId> AsyncCore::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  return tc::async_resumable([=]() -> tc::cotask<SGroupId> {
    TC_RETURN(TC_AWAIT(this->_core->createGroup(members)));
  });
}

tc::future<void> AsyncCore::updateGroupMembers(
    SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->updateGroupMembers(groupId, usersToAdd));
  });
}

tc::future<UnlockKey> AsyncCore::generateAndRegisterUnlockKey()
{
  return tc::async_resumable([this]() -> tc::cotask<UnlockKey> {
    TC_RETURN(TC_AWAIT(this->_core->generateAndRegisterUnlockKey()));
  });
}

tc::future<void> AsyncCore::registerUnlock(
    Unlock::RegistrationOptions const& options)
{
  return tc::async_resumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->registerUnlock(options));
  });
}

tc::future<bool> AsyncCore::isUnlockAlreadySetUp() const
{
  return tc::async_resumable([this]() -> tc::cotask<bool> {
    TC_RETURN(TC_AWAIT(this->_core->isUnlockAlreadySetUp()));
  });
}

expected<Unlock::Methods> AsyncCore::registeredUnlockMethods() const
{
  return tc::sync([&] { return this->_core->registeredUnlockMethods(); });
}

expected<bool> AsyncCore::hasRegisteredUnlockMethods() const
{
  return tc::sync([&] { return this->_core->hasRegisteredUnlockMethods(); });
}

expected<bool> AsyncCore::hasRegisteredUnlockMethod(
    Unlock::Method method) const
{
  return tc::sync(
      [&] { return this->_core->hasRegisteredUnlockMethod(method); });
}

tc::future<SDeviceId> AsyncCore::deviceId() const
{
  return tc::async(
      [this]() { return SDeviceId(base64::encode(this->_core->deviceId())); });
}

tc::future<void> AsyncCore::revokeDevice(SDeviceId const& deviceId)
{
  return tc::async_resumable([this, deviceId]() -> tc::cotask<void> {
    TC_AWAIT(
        this->_core->revokeDevice(base64::decode<DeviceId>(deviceId.string())));
  });
}

tc::future<void> AsyncCore::syncTrustchain()
{
  return tc::async_resumable([this]() -> tc::cotask<void> {
    TC_AWAIT(this->_core->syncTrustchain());
  });
}

boost::signals2::signal<void()>& AsyncCore::sessionClosed()
{
  return this->_core->sessionClosed;
}

boost::signals2::signal<void()>& AsyncCore::deviceCreated()
{
  return this->_core->deviceCreated;
}

boost::signals2::signal<void()>& AsyncCore::deviceRevoked()
{
  return this->_core->deviceRevoked;
}

void AsyncCore::setLogHandler(Log::LogHandler handler)
{
  // android's libart doesn't like it when we call java from a coroutine
  static tc::thread_pool tp;
  if (!tp.is_running())
    tp.start(1);
  Log::setLogHandler(
      [=](auto... args) { tc::async(tp, [=] { handler(args...); }).get(); });
}

uint64_t AsyncCore::encryptedSize(uint64_t clearSize)
{
  return Encryptor::encryptedSize(clearSize);
}

expected<uint64_t> AsyncCore::decryptedSize(
    gsl::span<uint8_t const> encryptedData)
{
  return tc::sync([&] { return Encryptor::decryptedSize(encryptedData); });
}

expected<SResourceId> AsyncCore::getResourceId(
    gsl::span<uint8_t const> encryptedData)
{
  return tc::sync([&] { return Core::getResourceId(encryptedData); });
}

std::string const& AsyncCore::version()
{
  return TANKER_VERSION;
}
}
