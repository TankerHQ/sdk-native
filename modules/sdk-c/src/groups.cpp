#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

#include <tconcurrent/async.hpp>

#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/Utils.hpp>

using namespace Tanker;

tanker_future_t* tanker_create_group(
    tanker_t* ctanker,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add)
{
  return makeFuture(
      tc::sync([&] {
        auto const members =
            to_vector<SPublicIdentity>(public_identities_to_add,
                                       nb_public_identities_to_add,
                                       "public_identities");
        auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);

        return tanker->createGroup(members);
      })
          .unwrap()
          .and_then(tc::get_synchronous_executor(), [](auto const& id) {
            return static_cast<void*>(duplicateString(id.string()));
          }));
}

tanker_future_t* tanker_update_group_members(
    tanker_t* ctanker,
    char const* group_id,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add,
    char const* const* public_identities_to_remove,
    uint64_t nb_public_identities_to_remove)
{
  return makeFuture(
      tc::sync([&] {
        auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
        auto const public_identities_to_add_vec =
            to_vector<SPublicIdentity>(public_identities_to_add,
                                       nb_public_identities_to_add,
                                       "users_to_add");
        auto const public_identities_to_remove_vec =
            to_vector<SPublicIdentity>(public_identities_to_remove,
                                       nb_public_identities_to_remove,
                                       "users_to_remove");

        return tanker->updateGroupMembers(SGroupId{group_id},
                                          public_identities_to_add_vec,
                                          public_identities_to_remove_vec);
      }).unwrap());
}
