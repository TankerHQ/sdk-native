#include <Tanker/TransparentSession/Accessor.hpp>

#include <Tanker/Crypto/Crypto.hpp>

constexpr const uint64_t SESSION_EXPIRATION_SECONDS = 12 * 3600;

namespace Tanker::TransparentSession
{
bool operator==(AccessorResult const& lhs, AccessorResult const& rhs)
{
  return std::tie(lhs.key, lhs.id) == std::tie(rhs.key, rhs.id);
}

bool operator!=(AccessorResult const& lhs, AccessorResult const& rhs)
{
  return !(lhs == rhs);
}

Accessor::Accessor(Store* store, SessionShareCallback shareCallback)
  : _shareCallback(std::move(shareCallback)), _store(store)
{
}

tc::cotask<AccessorResult> Accessor::getOrCreateTransparentSession(std::vector<SPublicIdentity> const& users,
                                                                   std::vector<SGroupId> const& groups)
{
  auto const hash = Store::hashRecipients(users, groups);

  auto const resultVec = TC_AWAIT(_cache.run(
      [&](auto const& hashSpan) -> tc::cotask<AccessorResults> {
        auto const& hash = hashSpan[0];
        if (auto sess = TC_AWAIT(_store->get(hash)); sess.has_value())
        {
          // Enforce expiration of transparent session
          // Drop sessions in the future, since their real age is unknown
          auto const now = secondsSinceEpoch();
          if (sess->creationTimestamp <= now && now < sess->creationTimestamp + SESSION_EXPIRATION_SECONDS)
            TC_RETURN((AccessorResults{AccessorResult{hash, sess->sessionId, sess->sessionKey}}));
        }

        auto id = Crypto::getRandom<Crypto::SimpleResourceId>();
        auto key = Crypto::makeSymmetricKey();
        auto sess = AccessorResult{hash, id, key};
        TC_AWAIT(_shareCallback(sess, users, groups));
        TC_AWAIT(_store->put(hash, id, key));
        TC_RETURN(AccessorResults{sess});
      },
      gsl::span<Crypto::Hash const>{&hash, 1}));
  TC_RETURN(std::move(resultVec[0]));
}
}
