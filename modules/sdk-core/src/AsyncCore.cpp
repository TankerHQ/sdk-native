#include <Tanker/AsyncCore.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Version.hpp>

#include <mgs/base64.hpp>
#include <optional>
#include <tconcurrent/async.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/lazy/async.hpp>
#include <tconcurrent/lazy/sink_receiver.hpp>
#include <tconcurrent/lazy/then.hpp>

#include <boost/scope_exit.hpp>

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
auto makeEventHandler(tc::lazy::task_canceler& taskCanceler, std::function<void()> cb)
{
  auto cancelableSender = taskCanceler.wrap(tc::lazy::then(tc::lazy::async(tc::get_default_executor()), cb));
  return [cancelableSender = std::move(cancelableSender), cb = std::move(cb)]() mutable {
    cancelableSender.submit(tc::lazy::sink_receiver{});
  };
}
}

template <typename F>
auto AsyncCore::runResumable(F&& f)
{
  using Func = std::decay_t<F>;
  using ReturnValue = typename tc::detail::task_return_type<std::invoke_result_t<F>>::type;

  return tc::submit_to_future<ReturnValue>(_taskCanceler.wrap(tc::lazy::connect(
      tc::lazy::async(tc::get_default_executor()),
      tc::lazy::run_resumable(
          tc::get_default_executor(), {}, &AsyncCore::runResumableImpl<Func>, this, std::forward<F>(f)))));
}

template <typename F>
std::invoke_result_t<F> AsyncCore::runResumableImpl(F f)
{
  if (_stopping)
    // Throw the same exception as if tconcurrent had canceled the call itself
    throw tc::operation_canceled{};

  bool isUnusable = false;
  std::exception_ptr eptr;
  try
  {
    if constexpr (std::is_same_v<std::invoke_result_t<F>, tc::cotask<void>>)
    {
      TC_AWAIT(f());
      TC_RETURN();
    }
    else
    {
      TC_RETURN(TC_AWAIT(f()));
    }
  }
  catch (Errors::Exception const& ex)
  {
    eptr = std::current_exception();
    if (ex.errorCode() == Errors::AppdErrc::InvalidChallengePublicKey ||
        ex.errorCode() == Errors::AppdErrc::InvalidChallengeSignature ||
        ex.errorCode() == Errors::AppdErrc::DeviceNotFound)
    {
      eptr = std::current_exception();
      TERROR("Device is unusable: {}", ex.what());
      isUnusable = true;
    }
    else
      throw;
  }
  if (isUnusable)
  {
    TC_AWAIT(handleDeviceUnrecoverable());
    std::rethrow_exception(eptr);
  }
  throw Errors::AssertionError("unreachable code in runResumable");
}

AsyncCore::AsyncCore(std::string url,
                     SdkInfo info,
                     std::string dataPath,
                     std::string cachePath,
                     std::unique_ptr<Network::Backend> networkBackend,
                     std::unique_ptr<DataStore::Backend> datastoreBackend)
  : _core(std::move(url),
          std::move(info),
          std::move(dataPath),
          std::move(cachePath),
          std::move(networkBackend),
          std::move(datastoreBackend))
{
}

AsyncCore::~AsyncCore()
{
  assert(tc::get_default_executor().is_in_this_context());
  // stop() calls aren't put in the task canceler, so cancel it explicitly
  if (_cancelStop)
    _cancelStop();
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
  return runResumable([=, this]() -> tc::cotask<Status> { TC_RETURN(TC_AWAIT(this->_core.start(identity))); });
}

tc::future<void> AsyncCore::enrollUser(std::string const& identity,
                                       std::vector<Verification::Verification> const& verifications)
{
  return runResumable([=, this]() -> tc::cotask<void> { TC_AWAIT(this->_core.enrollUser(identity, verifications)); });
}

tc::future<std::optional<std::string>> AsyncCore::registerIdentity(Verification::Verification const& verification,
                                                                   Core::VerifyWithToken withToken)
{
  return runResumable([=, this]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.registerIdentity(verification, withToken)));
  });
}

tc::future<std::optional<std::string>> AsyncCore::verifyIdentity(Verification::Verification const& verification,
                                                                 Core::VerifyWithToken withToken)
{
  return runResumable([=, this]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.verifyIdentity(verification, withToken)));
  });
}

tc::future<void> AsyncCore::stop()
{
  // Do not try to stop twice at the same time
  if (_stopping.exchange(true))
    return tc::make_exceptional_future<void>(
        Errors::formatEx(Errors::Errc::PreconditionFailed, "the Tanker session is already stopping"));

  auto fut = tc::async_resumable([&]() -> tc::cotask<void> {
    BOOST_SCOPE_EXIT_ALL(&)
    {
      _stopping = false;
    };

    // Terminate all calls so that we can stop and delete stuff safely. Note
    // that the current call will not be canceled because we didn't add its
    // future to the task canceler.
    _taskCanceler.terminate();

    TC_AWAIT(this->_core.stop());
  });
  _cancelStop = fut.make_canceler();

  return fut;
}

tc::future<Oidc::Nonce> AsyncCore::createOidcNonce()
{
  return runResumable([=, this]() -> tc::cotask<Oidc::Nonce> { TC_RETURN(TC_AWAIT(this->_core.createOidcNonce())); });
}

tc::future<void> AsyncCore::setOidcTestNonce(Oidc::Nonce const& nonce)
{
  return tc::sync([=, this]() { this->_core.setOidcTestNonce(nonce); });
}

Tanker::Status AsyncCore::status() const
{
  return this->_core.status();
}

tc::future<void> AsyncCore::encrypt(gsl::span<uint8_t> encryptedData,
                                    gsl::span<uint8_t const> clearData,
                                    std::vector<SPublicIdentity> const& publicIdentities,
                                    std::vector<SGroupId> const& groupIds,
                                    Core::ShareWithSelf shareWithSelf,
                                    std::optional<uint32_t> paddingStep)
{
  return runResumable([=, this]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.encrypt(encryptedData, clearData, publicIdentities, groupIds, shareWithSelf, paddingStep));
  });
}

tc::future<uint64_t> AsyncCore::decrypt(gsl::span<uint8_t> decryptedData, gsl::span<uint8_t const> encryptedData)
{
  return runResumable(
      [=, this]() -> tc::cotask<uint64_t> { TC_RETURN(TC_AWAIT(this->_core.decrypt(decryptedData, encryptedData))); });
}

tc::future<std::vector<uint8_t>> AsyncCore::encrypt(gsl::span<uint8_t const> clearData,
                                                    std::vector<SPublicIdentity> const& publicIdentities,
                                                    std::vector<SGroupId> const& groupIds,
                                                    Core::ShareWithSelf shareWithSelf,
                                                    std::optional<uint32_t> paddingStep)
{
  return runResumable([=, this]() -> tc::cotask<std::vector<uint8_t>> {
    TC_RETURN(TC_AWAIT(_core.encrypt(clearData, publicIdentities, groupIds, shareWithSelf, paddingStep)));
  });
}

tc::future<std::vector<uint8_t>> AsyncCore::decrypt(gsl::span<uint8_t const> encryptedData)
{
  return runResumable([=, this]() -> tc::cotask<std::vector<uint8_t>> {
    std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
    auto const clearSize = TC_AWAIT(_core.decrypt(decryptedData, encryptedData));
    decryptedData.resize(clearSize);
    TC_RETURN(std::move(decryptedData));
  });
}

tc::future<void> AsyncCore::share(std::vector<SResourceId> const& resourceId,
                                  std::vector<SPublicIdentity> const& publicIdentities,
                                  std::vector<SGroupId> const& groupIds)
{
  return runResumable(
      [=, this]() -> tc::cotask<void> { TC_AWAIT(this->_core.share(resourceId, publicIdentities, groupIds)); });
}

tc::future<SGroupId> AsyncCore::createGroup(std::vector<SPublicIdentity> const& members)
{
  return runResumable([=, this]() -> tc::cotask<SGroupId> { TC_RETURN(TC_AWAIT(this->_core.createGroup(members))); });
}

tc::future<void> AsyncCore::updateGroupMembers(SGroupId const& groupId,
                                               std::vector<SPublicIdentity> const& usersToAdd,
                                               std::vector<SPublicIdentity> const& usersToRemove)
{
  return runResumable([=, this]() -> tc::cotask<void> {
    TC_AWAIT(this->_core.updateGroupMembers(groupId, usersToAdd, usersToRemove));
  });
}

tc::future<VerificationKey> AsyncCore::generateVerificationKey()
{
  return runResumable(
      [this]() -> tc::cotask<VerificationKey> { TC_RETURN(TC_AWAIT(this->_core.generateVerificationKey())); });
}

tc::future<std::optional<std::string>> AsyncCore::setVerificationMethod(Verification::Verification const& method,
                                                                        Core::VerifyWithToken withToken,
                                                                        Core::AllowE2eMethodSwitch allowE2eSwitch)
{
  return runResumable([=, this]() -> tc::cotask<std::optional<std::string>> {
    TC_RETURN(TC_AWAIT(this->_core.setVerificationMethod(method, withToken, allowE2eSwitch)));
  });
}

tc::future<std::vector<Verification::VerificationMethod>> AsyncCore::getVerificationMethods()
{
  return runResumable([=, this]() -> tc::cotask<std::vector<Verification::VerificationMethod>> {
    TC_RETURN(TC_AWAIT(this->_core.getVerificationMethods()));
  });
}

tc::future<AttachResult> AsyncCore::attachProvisionalIdentity(SSecretProvisionalIdentity const& sidentity)
{
  return runResumable([=, this]() -> tc::cotask<AttachResult> {
    TC_RETURN(TC_AWAIT(this->_core.attachProvisionalIdentity(sidentity)));
  });
}

tc::future<void> AsyncCore::verifyProvisionalIdentity(Verification::Verification const& verification)
{
  return runResumable(
      [=, this]() -> tc::cotask<void> { TC_AWAIT(this->_core.verifyProvisionalIdentity(verification)); });
}

tc::future<OidcAuthorizationCode> AsyncCore::authenticateWithIdp(std::string const& provider_id,
                                                                 std::string const& cookie)
{
  return runResumable([=, this]() -> tc::cotask<OidcAuthorizationCode> {
    TC_RETURN(TC_AWAIT(this->_core.authenticateWithIdp(provider_id, cookie)));
  });
}

void AsyncCore::connectSessionClosed(std::function<void()> cb)
{
  this->_core.setSessionClosedHandler(makeEventHandler(this->_taskCanceler, std::move(cb)));
}

void AsyncCore::disconnectSessionClosed()
{
  this->_core.setSessionClosedHandler(nullptr);
}

void AsyncCore::setLogHandler(Log::LogHandler handler)
{
  Log::setLogHandler(
      [handler](Log::Record const& record) { tc::dispatch_on_thread_context([&] { handler(record); }); });
}

uint64_t AsyncCore::encryptedSize(uint64_t clearSize, std::optional<uint32_t> paddingStep)
{
  return Encryptor::encryptedSize(clearSize, paddingStep);
}

expected<uint64_t> AsyncCore::decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  return tc::sync([&] { return Encryptor::decryptedSize(encryptedData); });
}

expected<SResourceId> AsyncCore::getResourceId(gsl::span<uint8_t const> encryptedData)
{
  return tc::sync([&] { return mgs::base64::encode<SResourceId>(Core::getResourceId(encryptedData)); });
}

tc::future<std::tuple<Streams::InputSource, Crypto::ResourceId>> AsyncCore::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& suserIds,
    std::vector<SGroupId> const& sgroupIds,
    Core::ShareWithSelf shareWithSelf,
    std::optional<uint32_t> paddingStep)
{
  return runResumable(
      [=, this, cb = std::move(cb)]() -> tc::cotask<std::tuple<Streams::InputSource, Crypto::ResourceId>> {
        TC_RETURN(
            TC_AWAIT(this->_core.makeEncryptionStream(std::move(cb), suserIds, sgroupIds, shareWithSelf, paddingStep)));
      });
}

tc::future<std::tuple<Streams::InputSource, Crypto::ResourceId>> AsyncCore::makeDecryptionStream(
    Streams::InputSource cb)
{
  return runResumable([this, cb = std::move(cb)]() -> tc::cotask<std::tuple<Streams::InputSource, Crypto::ResourceId>> {
    TC_RETURN(TC_AWAIT(this->_core.makeDecryptionStream(std::move(cb))));
  });
}

tc::future<EncryptionSession> AsyncCore::makeEncryptionSession(std::vector<SPublicIdentity> const& publicIdentities,
                                                               std::vector<SGroupId> const& groupIds,
                                                               Core::ShareWithSelf shareWithSelf,
                                                               std::optional<uint32_t> paddingStep)
{
  return runResumable([=, this]() -> tc::cotask<EncryptionSession> {
    TC_RETURN(TC_AWAIT(this->_core.makeEncryptionSession(publicIdentities, groupIds, shareWithSelf, paddingStep)));
  });
}

tc::cotask<void> AsyncCore::handleDeviceUnrecoverable()
{
  auto const lock = TC_AWAIT(_quickStopSemaphore.get_scope_lock());

  nukeAndStop();
}

void AsyncCore::nukeAndStop()
{
  // - This device has been deemed unusable, we need to stop so
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

SdkInfo const& AsyncCore::sdkInfo()
{
  return this->_core.sdkInfo();
}

std::string const& AsyncCore::version()
{
  return TANKER_VERSION;
}

tc::future<void> AsyncCore::setHttpSessionToken(std::string token)
{
  return tc::async([this, tk = std::move(token)] { this->_core.setHttpSessionToken(std::move(tk)); });
}
}
