#include <Tanker/AsyncCore.hpp>

#include <Tanker/Core.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Version.hpp>

#include <cppcodec/base64_rfc4648.hpp>
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
  : _core(std::move(url), std::move(info), std::move(writablePath))
{
  _core.deviceRevoked.connect([this] {
    _taskCanceler.run([&] {
      return tc::async([this] {
        // - This device was revoked, we need to signOut so that Session gets
        // destroyed.
        // - There might be calls in progress on this session, so we must
        // terminate() them before going on.
        // - We can't call this->signOut() because the terminate() would cancel
        // this coroutine too.
        // - We must not wait on terminate() because that means waiting on
        // ourselves and deadlocking.
        _taskCanceler.terminate();
        _core.signOut();
        _asyncDeviceRevoked();
      });
    });
  });
}

AsyncCore::~AsyncCore() = default;

tc::future<void> AsyncCore::destroy()
{
  if (tc::get_default_executor().is_in_this_context())
    return tc::sync([this] { delete this; });
  else
    return tc::async([this] { delete this; });
}

expected<boost::signals2::scoped_connection> AsyncCore::connectEvent(
    Event event, std::function<void(void*, void*)> cb, void* data)
{
  return tc::sync([&] {
    return boost::signals2::scoped_connection([&] {
      switch (event)
      {
      case Event::SessionClosed:
        return this->_core.sessionClosed.connect([this, cb, data] {
          _taskCanceler.run(
              [&cb, &data] { return tc::async([=] { cb(nullptr, data); }); });
        });
      case Event::DeviceRevoked:
        return this->_asyncDeviceRevoked.connect([this, cb, data]() {
          _taskCanceler.run(
              [&cb, &data] { return tc::async([=] { cb(nullptr, data); }); });
        });
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

tc::shared_future<void> AsyncCore::signUp(
    std::string const& identity, AuthenticationMethods const& authMethods)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.signUp(identity, authMethods));
    });
  });
}

tc::shared_future<OpenResult> AsyncCore::signIn(
    std::string const& identity, SignInOptions const& signInOptions)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<OpenResult> {
      TC_RETURN(TC_AWAIT(this->_core.signIn(identity, signInOptions)));
    });
  });
}

tc::shared_future<void> AsyncCore::signOut()
{
  return _taskCanceler.run(
      [&] { return tc::async([this] { this->_core.signOut(); }); });
}

bool AsyncCore::isOpen() const
{
  return this->_core.isOpen();
}

tc::shared_future<void> AsyncCore::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.encrypt(
          encryptedData, clearData, publicIdentities, groupIds));
    });
  });
}

tc::shared_future<void> AsyncCore::decrypt(
    uint8_t* decryptedData, gsl::span<uint8_t const> encryptedData)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.decrypt(decryptedData, encryptedData));
    });
  });
}

tc::shared_future<void> AsyncCore::share(
    std::vector<SResourceId> const& resourceId,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.share(resourceId, publicIdentities, groupIds));
    });
  });
}

tc::shared_future<SGroupId> AsyncCore::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<SGroupId> {
      TC_RETURN(TC_AWAIT(this->_core.createGroup(members)));
    });
  });
}

tc::shared_future<void> AsyncCore::updateGroupMembers(
    SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.updateGroupMembers(groupId, usersToAdd));
    });
  });
}

tc::shared_future<UnlockKey> AsyncCore::generateAndRegisterUnlockKey()
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this]() -> tc::cotask<UnlockKey> {
      TC_RETURN(TC_AWAIT(this->_core.generateAndRegisterUnlockKey()));
    });
  });
}

tc::shared_future<void> AsyncCore::registerUnlock(
    Unlock::RegistrationOptions const& options)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.registerUnlock(options));
    });
  });
}

tc::shared_future<bool> AsyncCore::isUnlockAlreadySetUp() const
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this]() -> tc::cotask<bool> {
      TC_RETURN(TC_AWAIT(this->_core.isUnlockAlreadySetUp()));
    });
  });
}

expected<Unlock::Methods> AsyncCore::registeredUnlockMethods() const
{
  return tc::sync([&] { return this->_core.registeredUnlockMethods(); });
}

expected<bool> AsyncCore::hasRegisteredUnlockMethods() const
{
  return tc::sync([&] { return this->_core.hasRegisteredUnlockMethods(); });
}

expected<bool> AsyncCore::hasRegisteredUnlockMethod(Unlock::Method method) const
{
  return tc::sync(
      [&] { return this->_core.hasRegisteredUnlockMethod(method); });
}

expected<SDeviceId> AsyncCore::deviceId() const
{
  return tc::sync([&] {
    return SDeviceId(cppcodec::base64_rfc4648::encode(_core.deviceId()));
  });
}

tc::shared_future<std::vector<Device>> AsyncCore::getDeviceList()
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this]() -> tc::cotask<std::vector<Device>> {
      TC_AWAIT(syncTrustchain());
      auto devices = TC_AWAIT(this->_core.getDeviceList());
      devices.erase(std::remove_if(
          devices.begin(), devices.end(), [](auto const& device) {
            return device.isGhostDevice;
          }));
      TC_RETURN(devices);
    });
  });
}

tc::shared_future<void> AsyncCore::revokeDevice(SDeviceId const& deviceId)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this, deviceId]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.revokeDevice(
          cppcodec::base64_rfc4648::decode<Trustchain::DeviceId>(
              deviceId.string())));
    });
  });
}

tc::shared_future<void> AsyncCore::syncTrustchain()
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.syncTrustchain());
    });
  });
}

boost::signals2::signal<void()>& AsyncCore::sessionClosed()
{
  return this->_core.sessionClosed;
}

boost::signals2::signal<void()>& AsyncCore::deviceRevoked()
{
  return this->_asyncDeviceRevoked;
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
