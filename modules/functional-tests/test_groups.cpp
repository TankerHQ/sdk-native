#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Tanker/Functional/Session.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include "TestSuite.hpp"

#include <catch2/generators/catch_generators.hpp>

#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/concat.hpp>
#include <range/v3/view/drop.hpp>
#include <range/v3/view/join.hpp>
#include <range/v3/view/take.hpp>
#include <range/v3/view/transform.hpp>

#include "CheckDecrypt.hpp"
#include "CheckGroups.hpp"

using namespace Tanker;
using namespace Tanker::Functional;

namespace
{
struct GroupParameters
{
  int nbUsers;
  int nbProvisionalUsersEmail;
  int nbProvisionalUsersPhoneNumber;

  std::string toString() const
  {
    return fmt::format(
        "{} users, {} email provisional users, {} phone number provisional "
        "users",
        nbUsers,
        nbProvisionalUsersEmail,
        nbProvisionalUsersPhoneNumber);
  }
};

void duplicateMembers(
    std::vector<SPublicIdentity>& publicIdentities,
    GroupParameters const& config,
    std::vector<UserSession> const& users,
    std::vector<ProvisionalUserSession> const& provisionalUsers)
{
  if (config.nbUsers > 0)
    publicIdentities.push_back(users[0].spublicIdentity());
  if (config.nbProvisionalUsersEmail + config.nbProvisionalUsersPhoneNumber > 0)
    publicIdentities.push_back(provisionalUsers[0].spublicIdentity());
}
}

// Create group

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "create group with any kind of members",
                 "[groups][create]")
{
  auto const config = GENERATE(GroupParameters{1, 0, 0},
                               GroupParameters{2, 0, 0},
                               GroupParameters{0, 1, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 1},
                               GroupParameters{0, 0, 2},
                               GroupParameters{1, 1, 1},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, config.nbUsers);
  auto provisionalUsers =
      generate<ProvisionalUserSession>(trustchain,
                                       config.nbProvisionalUsersEmail,
                                       config.nbProvisionalUsersPhoneNumber);

  auto const publicIdentities = getPublicIdentities(users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup = TC_AWAIT(owner.session->createGroup(publicIdentities));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(myGroup,
                        {encryptedBuffer},
                        ranges::views::concat(users, provisionalUsers),
                        {}));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "create group with duplicate members",
                 "[groups][create]")
{
  auto const config = GENERATE(GroupParameters{2, 0, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 2},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, config.nbUsers);
  auto provisionalUsers =
      generate<ProvisionalUserSession>(trustchain,
                                       config.nbProvisionalUsersEmail,
                                       config.nbProvisionalUsersPhoneNumber);

  auto publicIdentities = getPublicIdentities(users, provisionalUsers);

  duplicateMembers(publicIdentities, config, users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup = TC_AWAIT(owner.session->createGroup(publicIdentities));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(myGroup,
                        {encryptedBuffer},
                        ranges::views::concat(users, provisionalUsers),
                        {}));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup with an empty list",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(alice.session->createGroup({})),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup with invalid identities",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->createGroup({SPublicIdentity{"AAAA="}})),
      Errors::Errc::InvalidArgument,
      "AAAA=");
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup an unknown user",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  auto user = trustchain.makeUser();
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->createGroup({user.spublicIdentity()})),
      Errors::Errc::InvalidArgument,
      user.spublicIdentity().string());
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup with a user from another trustchain",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  auto const otherTrustchainId = "gOhJDFYKK/GNScGOoaZ1vLAwxkuqZCY36IwEo4jcnDE=";
  auto const otherTrustchainSecret =
      "D9jiQt7nB2IlRjilNwUVVTPsYkfbCX0PelMzx5AAXIaVokZ71iUduWCvJ9Akzojca6lvV8u1"
      "rnDVEdh7yO6JAQ==";
  auto const wrongIdentity = Identity::createIdentity(
      otherTrustchainId, otherTrustchainSecret, "someone");
  auto const wrongPublicIdentity =
      SPublicIdentity{Identity::getPublicIdentity(wrongIdentity)};
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->createGroup({wrongPublicIdentity})),
      Errors::Errc::InvalidArgument,
      "not in the trustchain");
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup with an attached provisional identity",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  auto provisionalUser = ProvisionalUserSession(trustchain);
  TC_AWAIT(provisionalUser.attach());
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->createGroup({provisionalUser.spublicIdentity()})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup with too many users",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);

  std::vector<SPublicIdentity> identities;
  for (unsigned int i = 0; i < Groups::Manager::MAX_GROUP_SIZE + 1; ++i)
    identities.push_back(SPublicIdentity(to_string(
        Identity::getPublicIdentity(Identity::createProvisionalIdentity(
            trustchain.id, Email{fmt::format("bobtest{}@tanker.io", i)})))));
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->createGroup(identities)),
      Errors::Errc::GroupTooBig);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "createGroup without self in group",
                 "[groups][create]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto const groupId =
      TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*bob.session, {}, {groupId}));

  TC_AWAIT(checkGroup(groupId, {encryptedBuffer}, {}, {alice}));

  TC_AWAIT(alice.session->stop());

  // We can't assert this with decrypt because the server will not send the key
  // publish. This is the only way I have found to assert that.
  auto dbPath = fmt::format("{}/{}",
                            alice.device.writablePath(),
                            mgs::base64url::encode(alice.user.userId()));
  auto db = DataStore::SqliteBackend().open(dbPath, dbPath);
  auto store = Groups::Store(alice.user.userSecret(), db.get());
  auto const group = TC_AWAIT(store.findById(
      mgs::base64::decode<Tanker::Trustchain::GroupId>(groupId)));
  REQUIRE(group);
  CHECK(boost::variant2::holds_alternative<ExternalGroup>(*group));
}

// Add to group

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "add any kind of members to group",
                 "[groups][add]")
{
  auto const config = GENERATE(GroupParameters{1, 0, 0},
                               GroupParameters{2, 0, 0},
                               GroupParameters{0, 1, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 1},
                               GroupParameters{0, 0, 2},
                               GroupParameters{1, 1, 1},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, config.nbUsers);
  auto provisionalUsers =
      generate<ProvisionalUserSession>(trustchain,
                                       config.nbProvisionalUsersEmail,
                                       config.nbProvisionalUsersPhoneNumber);

  auto const publicIdentities = getPublicIdentities(users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup =
        TC_AWAIT(owner.session->createGroup({owner.spublicIdentity()}));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    REQUIRE_NOTHROW(TC_AWAIT(
        owner.session->updateGroupMembers(myGroup, publicIdentities, {})));

    auto const encryptedBuffer2 =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(myGroup,
                        {encryptedBuffer, encryptedBuffer2},
                        ranges::views::concat(users, provisionalUsers),
                        {}));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "add duplicate members to groups",
                 "[groups][add]")
{
  auto const config = GENERATE(GroupParameters{2, 0, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 2},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, config.nbUsers);
  auto provisionalUsers =
      generate<ProvisionalUserSession>(trustchain,
                                       config.nbProvisionalUsersEmail,
                                       config.nbProvisionalUsersPhoneNumber);

  auto publicIdentities = getPublicIdentities(users, provisionalUsers);

  duplicateMembers(publicIdentities, config, users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup =
        TC_AWAIT(owner.session->createGroup({owner.spublicIdentity()}));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    REQUIRE_NOTHROW(TC_AWAIT(
        owner.session->updateGroupMembers(myGroup, publicIdentities, {})));

    auto const encryptedBuffer2 =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(myGroup,
                        {encryptedBuffer, encryptedBuffer2},
                        ranges::views::concat(users, provisionalUsers),
                        {}));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "add any kind of members multiple times to group",
                 "[groups][add]")
{
  auto const config = GENERATE(GroupParameters{2, 0, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 2},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, config.nbUsers);
  auto provisionalUsers =
      generate<ProvisionalUserSession>(trustchain,
                                       config.nbProvisionalUsersEmail,
                                       config.nbProvisionalUsersPhoneNumber);

  auto const publicIdentities = getPublicIdentities(users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup =
        TC_AWAIT(owner.session->createGroup({owner.spublicIdentity()}));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    REQUIRE_NOTHROW(TC_AWAIT(
        owner.session->updateGroupMembers(myGroup, publicIdentities, {})));
    REQUIRE_NOTHROW(TC_AWAIT(
        owner.session->updateGroupMembers(myGroup, publicIdentities, {})));

    auto const encryptedBuffer2 =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(myGroup,
                        {encryptedBuffer, encryptedBuffer2},
                        ranges::views::concat(users, provisionalUsers),
                        {}));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "add too many members at once",
                 "[groups][add]")
{
  auto alice = UserSession(trustchain);

  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  std::vector<SPublicIdentity> identities;
  for (unsigned int i = 0; i < Groups::Manager::MAX_GROUP_SIZE + 1; ++i)
    identities.push_back(SPublicIdentity(to_string(
        Identity::getPublicIdentity(Identity::createProvisionalIdentity(
            trustchain.id, Email{fmt::format("bobtest{}@tanker.io", i)})))));
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(groupId, identities, {})),
      Errors::Errc::GroupTooBig);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "transitively add users to a group",
                 "[groups][add]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto charlie = UserSession(trustchain);

  auto const groupId =
      TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));
  TC_AWAIT(bob.session->updateGroupMembers(
      groupId, {charlie.spublicIdentity()}, {}));
  TC_AWAIT(charlie.session->updateGroupMembers(
      groupId, {alice.spublicIdentity()}, {}));

  auto const encryptedBuffer =
      TC_AWAIT(encrypt(*charlie.session, {}, {groupId}));

  TC_AWAIT(checkGroup(groupId, {encryptedBuffer}, {alice, bob, charlie}, {}));
}

// Remove from group

namespace
{
auto makeRemoveTestViews(
    std::vector<UserSession> const& users,
    std::vector<ProvisionalUserSession> const& provisionalUsers,
    int nbUsers,
    int nbProvisionalUsers)
{
  auto usersToRemove = users | ranges::views::take(nbUsers);
  auto usersToKeep = users | ranges::views::drop(nbUsers);
  auto provisionalUsersToRemove =
      provisionalUsers | ranges::views::take(nbProvisionalUsers);
  auto provisionalUsersToKeep =
      provisionalUsers | ranges::views::drop(nbProvisionalUsers);
  return std::make_tuple(usersToRemove,
                         usersToKeep,
                         provisionalUsersToRemove,
                         provisionalUsersToKeep);
}
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "remove any kind of members from group",
                 "[groups][remove]")
{
  auto const config = GENERATE(GroupParameters{1, 0, 0},
                               GroupParameters{2, 0, 0},
                               GroupParameters{0, 1, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 1},
                               GroupParameters{0, 0, 2},
                               GroupParameters{1, 1, 1},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, 2);
  auto provisionalUsers = generate<ProvisionalUserSession>(trustchain, 2, 2);

  auto [usersToRemove,
        usersToKeep,
        provisionalUsersToRemove,
        provisionalUsersToKeep] =
      makeRemoveTestViews(users,
                          provisionalUsers,
                          config.nbUsers,
                          config.nbProvisionalUsersEmail +
                              config.nbProvisionalUsersPhoneNumber);

  auto const publicIdentities =
      getPublicIdentities(users, provisionalUsers, std::vector{owner});

  auto const publicIdentitiesToRemove =
      getPublicIdentities(usersToRemove, provisionalUsersToRemove);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup = TC_AWAIT(owner.session->createGroup(publicIdentities));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    REQUIRE_NOTHROW(TC_AWAIT(owner.session->updateGroupMembers(
        myGroup, {}, publicIdentitiesToRemove)));

    auto const encryptedBuffer2 =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(
        myGroup,
        {encryptedBuffer, encryptedBuffer2},
        ranges::views::concat(usersToKeep, provisionalUsersToKeep),
        ranges::views::concat(usersToRemove, provisionalUsersToRemove)));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "remove duplicate members from group",
                 "[groups][remove]")
{
  auto const config = GENERATE(GroupParameters{2, 0, 0},
                               GroupParameters{0, 2, 0},
                               GroupParameters{0, 0, 2},
                               GroupParameters{2, 2, 2});

  auto owner = UserSession(trustchain);

  auto users = generate<UserSession>(trustchain, 2);
  auto provisionalUsers = generate<ProvisionalUserSession>(trustchain, 2, 2);

  auto [usersToRemove,
        usersToKeep,
        provisionalUsersToRemove,
        provisionalUsersToKeep] =
      makeRemoveTestViews(users,
                          provisionalUsers,
                          config.nbUsers,
                          config.nbProvisionalUsersEmail +
                              config.nbProvisionalUsersPhoneNumber);

  auto const publicIdentitiesVecs = {getPublicIdentities(users),
                                     getPublicIdentities(provisionalUsers),
                                     std::vector{owner.spublicIdentity()}};
  auto const publicIdentities =
      ranges::views::join(publicIdentitiesVecs) | ranges::to<std::vector>;

  auto const publicIdentitiesToRemoveVecs = {
      getPublicIdentities(usersToRemove),
      getPublicIdentities(provisionalUsersToRemove)};
  auto publicIdentitiesToRemove =
      ranges::views::join(publicIdentitiesToRemoveVecs) |
      ranges::to<std::vector>;

  duplicateMembers(publicIdentitiesToRemove, config, users, provisionalUsers);

  DYNAMIC_SECTION(config.toString())
  {
    auto myGroup = TC_AWAIT(owner.session->createGroup(publicIdentities));

    auto const encryptedBuffer =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    REQUIRE_NOTHROW(TC_AWAIT(owner.session->updateGroupMembers(
        myGroup, {}, publicIdentitiesToRemove)));

    auto const encryptedBuffer2 =
        TC_AWAIT(encrypt(*owner.session, {}, {myGroup}));

    TC_AWAIT(attachProvisionalIdentities(provisionalUsers));
    TC_AWAIT(checkGroup(
        myGroup,
        {encryptedBuffer, encryptedBuffer2},
        ranges::views::concat(usersToKeep, provisionalUsersToKeep),
        ranges::views::concat(usersToRemove, provisionalUsersToRemove)));
  }
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with empty lists",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(groupId, {}, {})),
      Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with invalid identities",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {SPublicIdentity{"AAAA="}}, {})),
      Errors::Errc::InvalidArgument,
      "AAAA=");
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {}, {SPublicIdentity{"AAAA="}})),
      Errors::Errc::InvalidArgument,
      "AAAA=");
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with an unknown user",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  auto user = trustchain.makeUser();
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {user.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument,
      user.spublicIdentity().string());
  // Here we test a removal of a non-registered user, however the detected error
  // is not that the user is unknown but that the user is not a member of the
  // group.
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(alice.session->updateGroupMembers(
                                    groupId, {}, {user.spublicIdentity()})),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with a user from another trustchain",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  auto const otherTrustchainId = "gOhJDFYKK/GNScGOoaZ1vLAwxkuqZCY36IwEo4jcnDE=";
  auto const otherTrustchainSecret =
      "D9jiQt7nB2IlRjilNwUVVTPsYkfbCX0PelMzx5AAXIaVokZ71iUduWCvJ9Akzojca6lvV8u1"
      "rnDVEdh7yO6JAQ==";
  auto const wrongIdentity = Identity::createIdentity(
      otherTrustchainId, otherTrustchainSecret, "someone");
  auto const wrongPublicIdentity =
      SPublicIdentity{Identity::getPublicIdentity(wrongIdentity)};
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {wrongPublicIdentity}, {})),
      Errors::Errc::InvalidArgument,
      "not in the trustchain");
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members adding and removing the same user",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {bob.spublicIdentity()}, {bob.spublicIdentity()})),
      Errors::Errc::InvalidArgument,
      bob.spublicIdentity().string());
  auto provisionalUser2 = ProvisionalUserSession(trustchain);
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId,
          {provisionalUser2.spublicIdentity()},
          {provisionalUser2.spublicIdentity()})),
      Errors::Errc::InvalidArgument,
      provisionalUser2.spublicIdentity().string());
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with invalid group id",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(
          SGroupId{""}, {alice.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument);
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(
          SGroupId{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
          {alice.spublicIdentity()},
          {})),
      Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group members with an attached provisional identity",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto provisionalUser = ProvisionalUserSession(trustchain);
  auto const groupId = TC_AWAIT(alice.session->createGroup(
      {alice.spublicIdentity(), provisionalUser.spublicIdentity()}));
  TC_AWAIT(provisionalUser.attach());

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {provisionalUser.spublicIdentity()}, {})),
      Errors::Errc::IdentityAlreadyAttached);
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(alice.session->updateGroupMembers(
          groupId, {}, {provisionalUser.spublicIdentity()})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "remove a user who is not a member",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(alice.session->updateGroupMembers(
                                    groupId, {}, {bob.spublicIdentity()})),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "remove all group members",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);

  auto const groupId =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(alice.session->updateGroupMembers(
                                    groupId, {}, {alice.spublicIdentity()})),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update a group we are not part of",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto charlie = UserSession(trustchain);

  auto const groupId = TC_AWAIT(alice.session->createGroup(
      {alice.spublicIdentity(), charlie.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(bob.session->updateGroupMembers(
          groupId, {bob.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument,
      "not a member of this group");
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(bob.session->updateGroupMembers(
          groupId, {}, {charlie.spublicIdentity()})),
      Errors::Errc::InvalidArgument,
      "not a member of this group");
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "remove oneself from group",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto const groupId = TC_AWAIT(alice.session->createGroup(
      {alice.spublicIdentity(), bob.spublicIdentity()}));
  TC_AWAIT(alice.session->updateGroupMembers(
      groupId, {}, {alice.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*bob.session, {}, {groupId}));

  TC_AWAIT(checkGroup(groupId, {encryptedBuffer}, {}, {alice}));
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "update group with added and removed members",
                 "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto charlie = UserSession(trustchain);

  auto const groupId = TC_AWAIT(alice.session->createGroup(
      {alice.spublicIdentity(), charlie.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session, {}, {groupId}));

  TC_AWAIT(alice.session->updateGroupMembers(
      groupId, {bob.spublicIdentity()}, {charlie.spublicIdentity()}));

  TC_AWAIT(checkGroup(groupId, {encryptedBuffer}, {bob}, {charlie}));
}

TEST_CASE_METHOD(
    TrustchainFixtureSimple,
    "remove claimed provisional group members as a permanent identity",
    "[groups][remove]")
{
  auto alice = UserSession(trustchain);
  auto bob = ProvisionalUserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup(
      {alice.spublicIdentity(), bob.spublicIdentity()}));

  TC_AWAIT(bob.attach());

  TC_AWAIT(alice.session->updateGroupMembers(
      myGroup, {}, {bob.userSPublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session, {}, {myGroup}));

  TC_AWAIT(checkGroup(myGroup, {encryptedBuffer}, {}, {bob}));
}

// Encrypt and share

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "encrypt for two groups",
                 "[groups][share]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto charlie = UserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));
  auto myGroup2 =
      TC_AWAIT(alice.session->createGroup({charlie.spublicIdentity()}));

  auto const encryptedBuffer =
      TC_AWAIT(encrypt(*alice.session, {}, {myGroup, myGroup2}));

  TC_AWAIT(checkDecrypt({bob, charlie}, {encryptedBuffer}));
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "share with one group",
                 "[groups][share]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session));
  auto const resourceId =
      AsyncCore::getResourceId(encryptedBuffer.encryptedData).get();
  REQUIRE_NOTHROW(TC_AWAIT(alice.session->share({resourceId}, {}, {myGroup})));

  TC_AWAIT(checkDecrypt({bob}, {encryptedBuffer}));
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "share with duplicate group ID",
                 "[groups][share]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session));
  auto const resourceId =
      AsyncCore::getResourceId(encryptedBuffer.encryptedData).get();
  REQUIRE_NOTHROW(
      TC_AWAIT(alice.session->share({resourceId}, {}, {myGroup, myGroup})));

  TC_AWAIT(checkDecrypt({bob}, {encryptedBuffer}));
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "share with two groups",
                 "[groups][share]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);
  auto charlie = UserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));
  auto myGroup2 =
      TC_AWAIT(alice.session->createGroup({charlie.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session));
  auto const resourceId =
      AsyncCore::getResourceId(encryptedBuffer.encryptedData).get();
  REQUIRE_NOTHROW(
      TC_AWAIT(alice.session->share({resourceId}, {}, {myGroup, myGroup2})));

  TC_AWAIT(checkDecrypt({bob, charlie}, {encryptedBuffer}));
}

// Edge cases

TEST_CASE_METHOD(
    TrustchainFixtureSimple,
    "create group, verify group, attach provisional identity and decrypt",
    "[groups][edge]")
{
  auto alice = UserSession(trustchain);
  auto bob = ProvisionalUserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session, {}, {myGroup}));

  // Fetch the group and add it into the GroupStore as ExternalGroup
  TC_AWAIT(encrypt(*bob.session, {}, {myGroup}));

  TC_AWAIT(bob.attach());

  // Upgrade it to InternalGroup
  TC_AWAIT(checkDecrypt({bob}, {encryptedBuffer}));
}

TEST_CASE_METHOD(
    TrustchainFixtureSimple,
    "add to group, verify group, attach provisional identity and decrypt",
    "[groups][edge]")
{
  auto alice = UserSession(trustchain);
  auto bob = ProvisionalUserSession(trustchain);

  auto myGroup =
      TC_AWAIT(alice.session->createGroup({alice.spublicIdentity()}));

  auto const encryptedBuffer = TC_AWAIT(encrypt(*alice.session, {}, {myGroup}));

  REQUIRE_NOTHROW(TC_AWAIT(
      alice.session->updateGroupMembers(myGroup, {bob.spublicIdentity()}, {})));

  // Fetch the group and add it into the GroupStore as ExternalGroup
  TC_AWAIT(encrypt(*bob.session, {}, {myGroup}));

  TC_AWAIT(bob.attach());

  // Upgrade it to InternalGroup
  TC_AWAIT(checkDecrypt({bob}, {encryptedBuffer}));
}

TEST_CASE_METHOD(TrustchainFixtureSimple,
                 "decrypt when a key is shared through two groups",
                 "[groups][edge]")
{
  auto alice = UserSession(trustchain);
  auto bob = UserSession(trustchain);

  auto myGroup = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));
  auto myGroup2 = TC_AWAIT(alice.session->createGroup({bob.spublicIdentity()}));

  auto const encryptedBuffer =
      TC_AWAIT(encrypt(*alice.session, {}, {myGroup, myGroup2}));

  TC_AWAIT(checkDecrypt({bob}, {encryptedBuffer}));
}
