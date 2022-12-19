#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/ResourceKeys/KeysResult.hpp>
#include <Tanker/TaskCoalescer.hpp>
#include <Tanker/TransparentSession/Store.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <boost/container/flat_map.hpp>
#include <vector>

namespace Tanker::TransparentSession
{
struct AccessorResult
{
  Crypto::Hash recipientsHash;
  Crypto::SimpleResourceId id;
  Crypto::SymmetricKey key;
};
bool operator==(AccessorResult const& lhs, AccessorResult const& rhs);
bool operator!=(AccessorResult const& lhs, AccessorResult const& rhs);
using AccessorResults = std::vector<AccessorResult>;

using SessionShareCallback =
    std::function<tc::cotask<void>(AccessorResult const& session,
                                   std::vector<SPublicIdentity> const& users,
                                   std::vector<SGroupId> const& groups)>;

class Accessor
{
public:
  Accessor(Store* store, SessionShareCallback shareCallback);
  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  // NOTE: If sharing with self, add self to the users public identities
  tc::cotask<AccessorResult> getOrCreateTransparentSession(
      std::vector<SPublicIdentity> const& users,
      std::vector<SGroupId> const& groups);

private:
  SessionShareCallback _shareCallback;
  Store* _store;
  Tanker::TaskCoalescer<AccessorResult,
                        Crypto::Hash,
                        &AccessorResult::recipientsHash>
      _cache;
};
}
