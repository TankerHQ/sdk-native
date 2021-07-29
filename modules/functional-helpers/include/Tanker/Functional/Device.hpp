#pragma once

#include <Tanker/AsyncCore.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <tconcurrent/coroutine.hpp>

#include <Helpers/UniquePath.hpp>

#include <memory>
#include <string>
#include <utility>

namespace Tanker
{
class AsyncCore;

namespace Functional
{
using AsyncCorePtr = std::shared_ptr<AsyncCore>;

struct AsyncCoreDeleter
{
  void operator()(AsyncCore* core) const
  {
    core->destroy().get();
  }
};

template <typename... T>
std::unique_ptr<AsyncCore, AsyncCoreDeleter> makeAsyncCore(T&&... args)
{
  return std::unique_ptr<AsyncCore, AsyncCoreDeleter>(
      new AsyncCore(std::forward<T>(args)...));
}

enum class SessionType
{
  Cached,
  New,
};

class Device
{
public:
  static Passphrase const STRONG_PASSWORD_DO_NOT_LEAK;

  Device(std::string trustchainUrl,
         std::string trustchainId,
         std::string identity);

  AsyncCorePtr createCore(SessionType type);
  std::unique_ptr<AsyncCore> createAsyncCore();
  tc::cotask<AsyncCorePtr> open(SessionType type = SessionType::Cached);
  std::string const& identity() const;
  std::string writablePath() const;

  SdkInfo getSdkInfo();

private:
  std::string _trustchainUrl;
  std::string _trustchainId;
  std::string _identity;
  std::shared_ptr<UniquePath> _storage;
};
}
}
