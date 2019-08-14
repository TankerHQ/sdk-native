#include <Tanker/FakeAuthentication/FakeAuthentication.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <doctest.h>

#include <boost/algorithm/string/replace.hpp>

#include <cppcodec/base64_url.hpp>

#include <sodium.h>

#include <nlohmann/json.hpp>

using namespace Tanker;

struct FakeAuthFixture : public TrustchainFixture
{
  std::string const appId = cppcodec::base64_url::encode(trustchain.id);
  std::string const url =
      boost::replace_all_copy<std::string>(trustchain.url, "api.", "fakeauth.");
  FakeAuthentication::FakeAuthentication fakeAuth{appId, url};
};

namespace
{
std::string makeTestEmail()
{
  return fmt::format("bob{}@gmail.com", randombytes_random());
}
}

TEST_CASE_FIXTURE(FakeAuthFixture,
                  "returns a disposable permanent identity without an email")
{
  auto const privateIdentity = TC_AWAIT(fakeAuth.getPrivateIdentity());
  CHECK(!privateIdentity.provisionalIdentity);
}

TEST_CASE_FIXTURE(FakeAuthFixture,
                  "returns a permanent identity for the given email")
{
  auto const privateIdentity =
      TC_AWAIT(fakeAuth.getPrivateIdentity(makeTestEmail()));
  CHECK(!privateIdentity.provisionalIdentity);
}

TEST_CASE_FIXTURE(
    FakeAuthFixture,
    "returns the same permanent identity when requested multiple times")
{
  auto const email = makeTestEmail();

  auto const result1 = TC_AWAIT(fakeAuth.getPrivateIdentity(email));
  auto const result2 = TC_AWAIT(fakeAuth.getPrivateIdentity(email));

  CHECK(result1.permanentIdentity == result2.permanentIdentity);
  CHECK(result1.provisionalIdentity == result2.provisionalIdentity);
}

TEST_CASE_FIXTURE(
    FakeAuthFixture,
    "returns a list of public identities (provisional and permanent)")
{
  auto const email1 = makeTestEmail();
  auto const email2 = makeTestEmail();

  // email1 exists, while email2 is provisional
  auto const priv1 = TC_AWAIT(fakeAuth.getPrivateIdentity(email1));
  auto const publicIdentities =
      TC_AWAIT(fakeAuth.getPublicIdentities({email1, email2}));
  REQUIRE(publicIdentities.size() == 2);
  auto const priv2 = TC_AWAIT(fakeAuth.getPrivateIdentity(email2));

  CHECK(Identity::detail::extract(publicIdentities[0]) ==
        Identity::detail::extract(
            Identity::getPublicIdentity(priv1.permanentIdentity)));
  CHECK(Identity::detail::extract(publicIdentities[1]) ==
        Identity::detail::extract(
            Identity::getPublicIdentity(priv2.provisionalIdentity.value())));
}

TEST_CASE_FIXTURE(FakeAuthFixture,
                  "returns the proper public identity before and after the "
                  "private identity has been used")
{
  auto const email = makeTestEmail();

  auto const publicProvIdentity =
      TC_AWAIT(fakeAuth.getPublicIdentities({email})).at(0);
  auto const privateIdentity = TC_AWAIT(fakeAuth.getPrivateIdentity(email));
  auto const publicPermIdentity =
      TC_AWAIT(fakeAuth.getPublicIdentities({email})).at(0);

  CHECK(Identity::detail::extract(publicProvIdentity) ==
        Identity::detail::extract(Identity::getPublicIdentity(
            privateIdentity.provisionalIdentity.value())));
  CHECK(Identity::detail::extract(publicPermIdentity) ==
        Identity::detail::extract(
            Identity::getPublicIdentity(privateIdentity.permanentIdentity)));
}
