#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/ResourceKeys/KeysResult.hpp>
#include <Tanker/TaskCoalescer.hpp>
#include <Tanker/TransparentSession/Store.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <boost/container/flat_map.hpp>

namespace Tanker::TransparentSession
{
struct AccessorResult
{
  Crypto::Hash recipientsHash;
  Crypto::SimpleResourceId sessionId;
  Crypto::SymmetricKey sessionKey;
  bool isNew;
};

class Accessor
{
public:
  Accessor(Store* store);
  Accessor() = delete;
  Accessor(Accessor const&) = delete;
  Accessor(Accessor&&) = delete;
  Accessor& operator=(Accessor const&) = delete;
  Accessor& operator=(Accessor&&) = delete;

  // NOTE: If sharing with self, add self to the users public identities
  tc::cotask<AccessorResult> getOrCreateTransparentSession(
      std::vector<SPublicIdentity> const& users,
      std::vector<SGroupId> const& groups);
  tc::cotask<void> saveTransparentSession(AccessorResult const& session);

private:
  Store* _store;
};
}
