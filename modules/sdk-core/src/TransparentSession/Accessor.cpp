#include <Tanker/TransparentSession/Accessor.hpp>

#include <Tanker/Crypto/Crypto.hpp>

constexpr const uint64_t SESSION_EXPIRATION_SECONDS = 12 * 3600;

namespace Tanker::TransparentSession
{
Accessor::Accessor(Store* store) : _store(store)
{
}

tc::cotask<AccessorResult> Accessor::getOrCreateTransparentSession(
    std::vector<SPublicIdentity> const& users,
    std::vector<SGroupId> const& groups)
{
  auto const hash = Store::hashRecipients(users, groups);

  if (auto sess = TC_AWAIT(_store->get(hash)); sess.has_value())
  {
    // Enforce expiration of transparent session
    // Drop sessions in the future, since their real age is unknown
    auto const now = secondsSinceEpoch();
    if (sess->creationTimestamp <= now &&
        now < sess->creationTimestamp + SESSION_EXPIRATION_SECONDS)
      TC_RETURN(
          (AccessorResult{hash, sess->sessionId, sess->sessionKey, false}));
  }

  auto id = Crypto::getRandom<Crypto::SimpleResourceId>();
  auto key = Crypto::makeSymmetricKey();
  TC_RETURN((AccessorResult{hash, id, key, true}));
}

tc::cotask<void> Accessor::saveTransparentSession(AccessorResult const& session)
{
  TC_AWAIT(_store->put(
      session.recipientsHash, session.sessionId, session.sessionKey));
}
}
