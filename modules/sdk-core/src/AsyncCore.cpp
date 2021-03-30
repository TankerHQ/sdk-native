#include <Tanker/AsyncCore.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/DeviceUnusable.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Version.hpp>

#include <mgs/base64.hpp>
#include <tconcurrent/async.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/lazy/async.hpp>
#include <tconcurrent/lazy/sink_receiver.hpp>
#include <tconcurrent/lazy/then.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

TLOG_CATEGORY(AsyncCore);

namespace Tanker
{
namespace
{
auto makeEventHandler(tc::lazy::task_canceler& taskCanceler,
                      std::function<void()> cb)
{
  auto cancelableSender = taskCanceler.wrap(
      tc::lazy::then(tc::lazy::async(tc::get_default_executor()), cb));
  return [cancelableSender = std::move(cancelableSender),
          cb = std::move(cb)]() mutable {
    cancelableSender.submit(tc::lazy::sink_receiver{});
  };
}
}

template <typename F>
auto AsyncCore::runResumable(F&& f)
{
  using Func = std::decay_t<F>;
  return tc::submit_to_future<typename tc::detail::task_return_type<
      decltype(std::declval<F>()())>::type>(
      _taskCanceler.wrap(tc::lazy::connect(
          tc::lazy::async(tc::get_default_executor()),
          tc::lazy::run_resumable(
              tc::get_default_executor(),
              {},
              [](AsyncCore* core, Func f) -> decltype(f()) {
                bool isRevoked = false;
                bool isUnusable = false;
                std::exception_ptr eptr;
                try
                {
                  if constexpr (std::is_same_v<decltype(f()), void>)
                  {
                    TC_AWAIT(f());
                    TC_RETURN();
                  }
                  else
                  {
                    TC_RETURN(TC_AWAIT(f()));
                  }
                }
                catch (Errors::DeviceUnusable const& ex)
                {
                  eptr = std::current_exception();
                  TERROR("Device is unusable: {}", ex.what());
                  isUnusable = true;
                }
                catch (Errors::Exception const& ex)
                {
                  eptr = std::current_exception();
                  if (ex.errorCode() == Errors::AppdErrc::DeviceRevoked)
                  {
                    TINFO("Device is revoked: {}", ex.what());
                    isRevoked = true;
                  }
                  else
                    throw;
                }
                if (isRevoked)
                  TC_AWAIT(core->handleDeviceRevocation()); // this is noreturn
                else if (isUnusable)
                {
                  TC_AWAIT(core->handleDeviceUnrecoverable());
                  std::rethrow_exception(eptr);
                }
                else
                  throw Errors::AssertionError(
                      "unreachable code in runResumable");
              },
              this,
              std::forward<F>(f)))));
}

AsyncCore::AsyncCore(std::string url, SdkInfo info, std::string writablePath)
  : _core(std::move(url), std::move(info), std::move(writablePath))
{
}

AsyncCore::~AsyncCore()
{
  assert(tc::get_default_executor().is_in_this_context());
}

tc::future<void> AsyncCore::destroy()
{
  if (tc::get_default_executor().is_in_this_context())
    return tc::sync([this] { delete this; });
  else
    return tc::async([this] { delete this; });
}

tc::future<Status> AsyncCore::start(std::string const& identity)
{
  return runResumable([=]() -> tc::cotask<Status> {
    TC_RETURN(TC_AWAIT(this->_core.start(identity)));
  });
}

tc::future<std::optional<std::string>> AsyncCore::registerIdentity(
    Unlock::Verification const& verification, Core::VerifyWithToken withToken)
{
  return runResumable([=]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.registerIdentity(verification, withToken)));
  });
}

tc::future<std::optional<std::string>> AsyncCore::verifyIdentity(
    Unlock::Verification const& verification, Core::VerifyWithToken withToken)
{
  return runResumable([=]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.verifyIdentity(verification, withToken)));
  });
}

tc::future<void> AsyncCore::stop()
{
  return runResumable(
      [=]() -> tc::cotask<void> { TC_AWAIT(this->_core.stop()); });
}

Tanker::Status AsyncCore::status() const
{
  return this->_core.status();
}

tc::future<void> AsyncCore::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds,
    Core::ShareWithSelf shareWithSelf)
{
  return runResumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.encrypt(
        encryptedData, clearData, publicIdentities, groupIds, shareWithSelf));
  });
}

tc::future<void> AsyncCore::decrypt(uint8_t* decryptedData,
                                    gsl::span<uint8_t const> encryptedData)
{
  return runResumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.decrypt(decryptedData, encryptedData));
  });
}

tc::future<std::vector<uint8_t>> AsyncCore::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds,
    Core::ShareWithSelf shareWithSelf)
{
  return runResumable([=]() -> tc::cotask<std::vector<uint8_t>> {
    TC_RETURN(TC_AWAIT(
        _core.encrypt(clearData, publicIdentities, groupIds, shareWithSelf)));
  });
}

tc::future<std::vector<uint8_t>> AsyncCore::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  return runResumable([=]() -> tc::cotask<std::vector<uint8_t>> {
    std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
    TC_AWAIT(_core.decrypt(decryptedData.data(), encryptedData));
    TC_RETURN(std::move(decryptedData));
  });
}

tc::future<void> AsyncCore::share(
    std::vector<SResourceId> const& resourceId,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  return runResumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.share(resourceId, publicIdentities, groupIds));
  });
}

tc::future<SGroupId> AsyncCore::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  return runResumable([=]() -> tc::cotask<SGroupId> {
    TC_RETURN(TC_AWAIT(this->_core.createGroup(members)));
  });
}

tc::future<void> AsyncCore::updateGroupMembers(
    SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd)
{
  return runResumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.updateGroupMembers(groupId, usersToAdd));
  });
}

tc::future<VerificationKey> AsyncCore::generateVerificationKey()
{
  return runResumable([this]() -> tc::cotask<VerificationKey> {
    TC_RETURN(TC_AWAIT(this->_core.generateVerificationKey()));
  });
}

tc::future<std::optional<std::string>> AsyncCore::setVerificationMethod(
    Unlock::Verification const& method, Core::VerifyWithToken withToken)
{
  return runResumable([=]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.setVerificationMethod(method, withToken)));
  });
}

tc::future<std::vector<Unlock::VerificationMethod>>
AsyncCore::getVerificationMethods()
{
  return runResumable(
      [=]() -> tc::cotask<std::vector<Unlock::VerificationMethod>> {
        TC_RETURN(TC_AWAIT(this->_core.getVerificationMethods()));
      });
}

tc::future<AttachResult> AsyncCore::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  return runResumable([=]() -> tc::cotask<AttachResult> {
    TC_RETURN(TC_AWAIT(this->_core.attachProvisionalIdentity(sidentity)));
  });
}

tc::future<void> AsyncCore::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  return runResumable([=]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.verifyProvisionalIdentity(verification));
  });
}

tc::future<SDeviceId> AsyncCore::deviceId() const
{
  return tc::submit_to_future<SDeviceId>(_taskCanceler.wrap(tc::lazy::then(
      tc::lazy::async(tc::get_default_executor()),
      [this] { return SDeviceId(mgs::base64::encode(_core.deviceId())); })));
}

tc::future<std::vector<Users::Device>> AsyncCore::getDeviceList()
{
  return runResumable([this]() -> tc::cotask<std::vector<Users::Device>> {
    auto devices = TC_AWAIT(this->_core.getDeviceList());
    devices.erase(
        std::remove_if(devices.begin(), devices.end(), [](auto const& device) {
          return device.isGhostDevice();
        }));
    TC_RETURN(devices);
  });
}

tc::future<void> AsyncCore::revokeDevice(SDeviceId const& deviceId)
{
  return runResumable([this, deviceId]() -> tc::cotask<void> {
    TC_AWAIT(
        this->_core.revokeDevice(base64DecodeArgument<Trustchain::DeviceId>(
            deviceId.string(), "device id")));
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

namespace
{
tc::thread_pool* logThreadPool = nullptr;
}

tc::thread_pool& AsyncCore::getLogHandlerThreadPool()
{
  // Android's libart doesn't like it when we call java from a coroutine, so we
  // make a thread pool for logs.
  // This function is not thread safe, but since it's called only during init,
  // it's fine.
  if (!logThreadPool)
  {
    logThreadPool = new tc::thread_pool;
    logThreadPool->start(1);
  }
  return *logThreadPool;
}

void AsyncCore::stopLogHandlerThreadPool()
{
  delete logThreadPool;
}

void AsyncCore::setLogHandler(Log::LogHandler handler)
{
  auto& tp = getLogHandlerThreadPool();
  Log::setLogHandler([handler, &tp](Log::Record const& record) {
    tc::async(tp, [=] { handler(record); }).get();
  });
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
  return tc::sync([&] {
    return mgs::base64::encode<SResourceId>(Core::getResourceId(encryptedData));
  });
}

tc::future<Streams::EncryptionStream> AsyncCore::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& suserIds,
    std::vector<SGroupId> const& sgroupIds,
    Core::ShareWithSelf shareWithSelf)
{
  return runResumable(
      [=, cb = std::move(cb)]() -> tc::cotask<Streams::EncryptionStream> {
        TC_RETURN(TC_AWAIT(this->_core.makeEncryptionStream(
            std::move(cb), suserIds, sgroupIds, shareWithSelf)));
      });
}

tc::future<Streams::DecryptionStreamAdapter> AsyncCore::makeDecryptionStream(
    Streams::InputSource cb)
{
  return runResumable(
      [this,
       cb = std::move(cb)]() -> tc::cotask<Streams::DecryptionStreamAdapter> {
        TC_RETURN(TC_AWAIT(this->_core.makeDecryptionStream(std::move(cb))));
      });
}

tc::future<EncryptionSession> AsyncCore::makeEncryptionSession(
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds,
    Core::ShareWithSelf shareWithSelf)
{
  return runResumable([=]() -> tc::cotask<EncryptionSession> {
    TC_RETURN(TC_AWAIT(this->_core.makeEncryptionSession(
        publicIdentities, groupIds, shareWithSelf)));
  });
}

[[noreturn]] tc::cotask<void> AsyncCore::handleDeviceRevocation()
{
  // If multiple coroutines get here waiting for this lock, one will get the
  // lock and eventually call _taskCanceler.terminate() which will abort all the
  // other ones.
  auto const lock = TC_AWAIT(_quickStopSemaphore.get_scope_lock());

  std::exception_ptr deviceRevokedException;
  try
  {
    TDEBUG("Refreshing user to verify verification");
    TC_AWAIT(_core.confirmRevocation());
    TERROR("While trying to confirm revocation, didn't get any error");
    throw Errors::formatEx(
        Errors::Errc::InternalError,
        "server declared this device revoked, but it is not");
  }
  catch (Errors::Exception const& ex)
  {
    if (ex.errorCode() != Errors::Errc::DeviceRevoked)
    {
      TERROR("While trying to confirm revocation, got a different error: {}",
             ex.what());
      throw;
    }
    else
    {
      deviceRevokedException = std::current_exception();
    }
  }
  nukeAndStop();
  if (_asyncDeviceRevoked)
    _asyncDeviceRevoked();
  TINFO("Revocation handled, self-destruct complete");
  std::rethrow_exception(deviceRevokedException);
}

tc::cotask<void> AsyncCore::handleDeviceUnrecoverable()
{
  // See handleDeviceRevocation
  auto const lock = TC_AWAIT(_quickStopSemaphore.get_scope_lock());

  nukeAndStop();
}

void AsyncCore::nukeAndStop()
{
  // - This device was revoked or has been deemed unusable, we need to stop so
  // that Session gets destroyed.
  // - There might be calls in progress on this session, so we
  // must terminate() them before going on.
  // - We can't call this->stop() because the terminate() would
  // cancel this coroutine too.
  // - We must not wait on terminate() because that means waiting
  // on ourselves and deadlocking.
  _taskCanceler.terminate();
  // We have asked for termination of all running tasks, including this one.
  // From now on, we must not TC_AWAIT or we will be canceled.
  _core.nukeDatabase();
  _core.quickStop();
}

std::string const& AsyncCore::version()
{
  return TANKER_VERSION;
}

tc::future<void> AsyncCore::setHttpSessionToken(std::string token)
{
  return tc::async([this, tk = std::move(token)] {
    this->_core.setHttpSessionToken(std::move(tk));
  });
}
}
