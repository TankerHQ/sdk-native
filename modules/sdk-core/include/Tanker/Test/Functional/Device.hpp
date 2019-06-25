#pragma once

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

namespace Test
{
using AsyncCorePtr = std::shared_ptr<AsyncCore>;

enum class SessionType
{
  Cached,
  New,
};

class Device
{
public:
  Device(std::string trustchainUrl,
         std::string trustchainId,
         SUserId suserId,
         std::string identity);

  AsyncCorePtr createCore(SessionType type);
  std::unique_ptr<AsyncCore> createAsyncCore();
  tc::cotask<AsyncCorePtr> open(SessionType type = SessionType::Cached);
  SUserId const& suserId() const;
  std::string const& identity() const;

private:
  std::string _trustchainUrl;
  std::string _trustchainId;
  SUserId _suserId;
  std::string _identity;
  std::shared_ptr<UniquePath> _storage;

  // Since Device is copyable and since we want to share the cache between all
  // the device copies, we need a shared_ptr of shared_ptr
  // TLDR; Don't remove it or it will break
  std::shared_ptr<AsyncCorePtr> _cachedSession =
      std::make_shared<AsyncCorePtr>();
};
}
}
