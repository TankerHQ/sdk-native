#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>

#include <tconcurrent/async.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

using namespace Tanker;

tanker_future_t* tanker_create_group(tanker_t* ctanker,
                                     char const* const* member_uids,
                                     uint64_t nb_members)
{
  auto const members = to_vector<SUserId>(member_uids, nb_members);
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tanker->createGroup(members).and_then(
      tc::get_synchronous_executor(), [](auto const& id) {
        return static_cast<void*>(duplicateString(id.string()));
      }));
}

tanker_future_t* tanker_update_group_members(tanker_t* ctanker,
                                             char const* group_id,
                                             char const* const* users_to_add,
                                             uint64_t nb_users_to_add)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto const users_to_add_vec =
      to_vector<SUserId>(users_to_add, nb_users_to_add);

  return makeFuture(
      tanker->updateGroupMembers(SGroupId{group_id}, users_to_add_vec));
}
