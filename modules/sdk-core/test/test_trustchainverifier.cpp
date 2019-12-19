#include <Tanker/TrustchainVerifier.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <boost/variant2/variant.hpp>
#include <doctest.h>

#include <cstring>
#include <memory>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;

TEST_CASE("TrustchainVerifier")
{
  TrustchainBuilder builder;
  auto const rootEntry = builder.entries().front();

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  AWAIT_VOID(db->setTrustchainPublicSignatureKey(
      rootEntry.action()
          .get<Trustchain::Actions::TrustchainCreation>()
          .publicSignatureKey()));

  SUBCASE("verifies a valid trustchain creation")
  {
    auto const contactStore = builder.makeContactStoreWith({}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(rootEntry)));
  }

  SUBCASE("verifies a valid device creation")
  {
    auto const userResult = builder.makeUser3("bob");

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(userResult.entry)));
  }

  SUBCASE("verifies a valid deviceRevocation")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(deviceResult.entry)));
    auto const targetResult = builder.makeDevice3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(targetResult.entry)));

    auto bobUser = builder.findUser("bob");

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    auto const revokeEntry = builder.revokeDevice2(
        deviceResult.device, targetResult.device, *bobUser);

    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get());

    CHECK_NOTHROW(AWAIT_VOID(verifier.verify(revokeEntry)));
  }

  SUBCASE("throws if the author does not exist")
  {
    builder.makeUser3("bob");
    auto deviceResult = builder.makeDevice3("bob");
    ++const_cast<Crypto::Hash&>(deviceResult.entry.author())[0];

    auto const contactStore = builder.makeContactStoreWith({"bob"}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get());

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(verifier.verify(deviceResult.entry)),
        Verif::Errc::InvalidAuthor);
  }

  SUBCASE("second device creation throws if user does not exist")
  {
    auto const userResult = builder.makeUser3("bob");
    AWAIT_VOID(db->addTrustchainEntry(toVerifiedEntry(userResult.entry)));
    auto const deviceResult = builder.makeDevice3("bob");

    // Do not add user 'bob' to contactStore:
    auto const contactStore = builder.makeContactStoreWith({}, db.get());
    TrustchainVerifier const verifier(
        builder.trustchainId(), db.get(), contactStore.get());

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(verifier.verify(deviceResult.entry)),
        Verif::Errc::InvalidAuthor);
  }
}
