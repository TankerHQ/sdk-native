#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

#include <tconcurrent/async.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

using namespace Tanker;

tanker_future_t* tanker_create_group(
    tanker_t* ctanker,
    char const* const* members_public_identities,
    uint64_t nb_members)
{
  auto const members =
      to_vector<SPublicIdentity>(members_public_identities, nb_members);
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tanker->createGroup(members).and_then(
      tc::get_synchronous_executor(), [](auto const& id) {
        return static_cast<void*>(duplicateString(id.string()));
      }));
}

tanker_future_t* tanker_update_group_members(
    tanker_t* ctanker,
    char const* group_id,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto const public_identities_to_add_vec = to_vector<SPublicIdentity>(
      public_identities_to_add, nb_public_identities_to_add);

  return makeFuture(tanker->updateGroupMembers(SGroupId{group_id},
                                               public_identities_to_add_vec));
}
