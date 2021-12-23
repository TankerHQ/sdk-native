#pragma once

#include <Tanker/Types/SGroupId.hpp>

#include <Tanker/Functional/Session.hpp>

#include <tconcurrent/coroutine.hpp>

#include "CheckDecrypt.hpp"

template <typename T>
tc::cotask<void> checkUpdateGroup(T const& sessions,
                                  Tanker::SGroupId const& groupId)
{
  for (auto const& session : sessions)
    REQUIRE_NOTHROW(TC_AWAIT(session.session->updateGroupMembers(
        groupId, {session.userSPublicIdentity()}, {})));
}

template <typename T>
tc::cotask<void> checkUpdateGroupFails(T const& sessions,
                                       Tanker::SGroupId const& groupId)
{
  for (auto const& session : sessions)
    TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
        TC_AWAIT(session.session->updateGroupMembers(
            groupId, {session.userSPublicIdentity()}, {})),
        Tanker::Errors::Errc::InvalidArgument,
        "not a member of this group");
}

template <
    typename Buffers = std::vector<Tanker::EncryptedBuffer>,
    typename UsersInGroup = std::vector<Tanker::Functional::UserSession>,
    typename UsersNotInGroup = std::vector<Tanker::Functional::UserSession>>
tc::cotask<void> checkGroup(Tanker::SGroupId const& groupId,
                            Buffers buffers,
                            UsersInGroup usersInGroup,
                            UsersNotInGroup usersNotInGroup)
{
  TC_AWAIT(checkDecrypt(usersInGroup, buffers));
  TC_AWAIT(checkUpdateGroup(usersInGroup, groupId));
  TC_AWAIT(checkDecryptFails(usersNotInGroup, buffers));
  TC_AWAIT(checkUpdateGroupFails(usersNotInGroup, groupId));
};
