#ifndef CTANKER_SDK_TANKER_GROUPS_H
#define CTANKER_SDK_TANKER_GROUPS_H

#include <stdint.h>

#include <ctanker/async.h>
#include <ctanker/base64.h>
#include <ctanker/ctanker.h>
#include <ctanker/export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Create a group containing the given users.
 * Share a symetric key of an encrypted data with other users.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param public_identities_to_add Array of the group members' public
 * identities. \param nb_public_identities_to_add The number of members in
 * public_identities_to_add.
 *
 * \return A future of the group ID as a string.
 * \throws TANKER_ERROR_USER_NOT_FOUND One of the members was not found, no
 * action was done
 * \throws TANKER_ERROR_INVALID_GROUP_SIZE The group is either empty, or has too
 * many members
 */
CTANKER_EXPORT tanker_future_t* tanker_create_group(
    tanker_t* session,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add);

/*!
 * Updates an existing group, referenced by its groupId,
 * adding the user identified by their user Ids to the group's members.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param group_id The group ID returned by tanker_create_group
 * \param public_identities_to_add Array of the new group members' public
 * identities. \param nb_public_identities_to_add The number of users in
 * public_identities_to_add.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_USER_NOT_FOUND One of the users was not found, no
 * action was done
 * \throws TANKER_ERROR_INVALID_GROUP_SIZE Too many users were added to the
 * group.
 */
CTANKER_EXPORT tanker_future_t* tanker_update_group_members(
    tanker_t* session,
    char const* group_id,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add);

#ifdef __cplusplus
}
#endif

#endif // CTANKER_SDK_TANKER_GROUPS_H
