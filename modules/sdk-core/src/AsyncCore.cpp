#include <Tanker/AsyncCore.hpp>

#include <Tanker/Core.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Version.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <tconcurrent/async.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <algorithm>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace Tanker
{
namespace
{
auto makeEventHandler(task_canceler& tc, std::function<void()> cb)

{
  return [&tc, cb = std::move(cb)] {
    tc.run([&cb] { return tc::async([cb = std::move(cb)] { cb(); }); });
  };
}
}

AsyncCore::AsyncCore(std::string url, SdkInfo info, std::string writablePath)
  : _core(std::move(url), std::move(info), std::move(writablePath))
{
  _core.setDeviceRevokedHandler([this] {
    _taskCanceler.run([&] {
      return tc::async([this] {
        // - This device was revoked, we need to stop so that Session gets
        // destroyed.
        // - There might be calls in progress on this session, so we must
        // terminate() them before going on.
        // - We can't call this->stop() because the terminate() would cancel
        // this coroutine too.
        // - We must not wait on terminate() because that means waiting on
        // ourselves and deadlocking.
        _taskCanceler.terminate();
        _core.stop();
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

tc::shared_future<Status> AsyncCore::start(std::string const& identity)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<Status> {
      TC_RETURN(TC_AWAIT(this->_core.start(identity)));
    });
  });
}

tc::shared_future<void> AsyncCore::registerIdentity(
    Unlock::Verification const& verification)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.registerIdentity(verification));
    });
  });
}

tc::shared_future<void> AsyncCore::verifyIdentity(
    Unlock::Verification const& verification)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.verifyIdentity(verification));
    });
  });
}

tc::shared_future<void> AsyncCore::stop()
{
  return _taskCanceler.run(
      [&] { return tc::async([this] { this->_core.stop(); }); });
}

Tanker::Status AsyncCore::status() const
{
  return this->_core.status();
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

tc::shared_future<VerificationKey> AsyncCore::generateVerificationKey()
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([this]() -> tc::cotask<VerificationKey> {
      TC_RETURN(TC_AWAIT(this->_core.generateVerificationKey()));
    });
  });
}

tc::shared_future<void> AsyncCore::setVerificationMethod(
    Unlock::Verification const& method)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.setVerificationMethod(method));
    });
  });
}

tc::shared_future<std::vector<Unlock::VerificationMethod>>
AsyncCore::getVerificationMethods()
{
  return _taskCanceler.run([&] {
    return tc::async_resumable(
        [=]() -> tc::cotask<std::vector<Unlock::VerificationMethod>> {
          TC_RETURN(TC_AWAIT(this->_core.getVerificationMethods()));
        });
  });
}

tc::shared_future<AttachResult> AsyncCore::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<AttachResult> {
      TC_RETURN(TC_AWAIT(this->_core.attachProvisionalIdentity(sidentity)));
    });
  });
}

tc::shared_future<void> AsyncCore::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  return _taskCanceler.run([&] {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      TC_AWAIT(this->_core.verifyProvisionalIdentity(verification));
    });
  });
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
          base64DecodeArgument<Trustchain::DeviceId>(deviceId.string())));
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

void AsyncCore::connectSessionClosed(std::function<void()> cb)
{
  this->_core.setSessionClosedHandler(
      makeEventHandler(this->_taskCanceler, std::move(cb)));
}

void AsyncCore::disconnectSessionClosed()
{
  this->_core.setSessionClosedHandler(nullptr);
}

void AsyncCore::connectDeviceRevoked(std::function<void()> cb)
{
  this->_asyncDeviceRevoked =
      makeEventHandler(this->_taskCanceler, std::move(cb));
}

void AsyncCore::disconnectDeviceRevoked()
{
  this->_asyncDeviceRevoked = nullptr;
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
