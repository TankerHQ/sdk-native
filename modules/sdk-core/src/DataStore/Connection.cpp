#include <Tanker/DataStore/Connection.hpp>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <Tanker/Log/Log.hpp>

#include <boost/algorithm/hex.hpp>
#include <sqlite3.h>
#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlpp11.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>

TLOG_CATEGORY(DataStore);

namespace Tanker
{
namespace DataStore
{
namespace
{
// clang-format off
SQLPP_DECLARE_TABLE(
  (access)
  ,
  (last_access, int, SQLPP_NOT_NULL)
)
// clang-format on

using Table = access::access;

void makeExclusive(ConnPtr& db)
{
  // This does not actually take the lock, we need to trigger a write operation
  // on the database for it to be taken. That's why we create a table and run an
  // update on it.
  db->execute(R"(
    PRAGMA locking_mode = EXCLUSIVE;
  )");
  db->execute(R"(
    CREATE TABLE IF NOT EXISTS access (
      last_access INT NOT NULL
    );
  )");

  Table access;

  // Yes, it actually (tries to) write, and takes the lock
  (*db)(update(access).set(access.last_access = 0).unconditionally());
}

bool isEncryptedDb(std::string const& dbPath)
{
  using namespace std::string_literals;

  std::ifstream ifs{dbPath, std::ios::binary | std::ios::in};
  if (!ifs.is_open())
    return hasCipher();
  auto const clearMagic = "SQLite format 3"s;
  std::string buffer(clearMagic.size(), 0);

  ifs.read(&buffer[0], clearMagic.size());
  return hasCipher() && buffer != clearMagic;
}

std::string hexUserSecret(std::optional<Crypto::SymmetricKey> const& userSecret)
{
  if (!userSecret)
    return {};
  std::string hexkey = "x'";
  boost::algorithm::hex(
      userSecret->begin(), userSecret->end(), std::back_inserter(hexkey));
  hexkey += "'";
  return hexkey;
}
}

ConnPtr createConnection(std::string const& dbPath,
                         std::optional<Crypto::SymmetricKey> userSecret,
                         bool exclusive)
{
  TINFO("creating database {}", dbPath);
  auto const isEncrypted = isEncryptedDb(dbPath);
  if (isEncrypted && !hasCipher())
  {
    throw Errors::formatEx(
        Errc::DatabaseError,
        "database {} is encrypted but OpenSSL support is not enabled",
        dbPath);
  }
  auto const shouldEncrypt = hasCipher() && isEncrypted;
  auto const shouldMigrate = hasCipher() && !isEncrypted && userSecret;
  try
  {
    auto db = [&] {
      SCOPE_TIMER("open", DB);
      return std::make_unique<Connection>(sqlpp::sqlite3::connection_config{
          dbPath.c_str(),
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
          "",
          false,
          shouldEncrypt ? hexUserSecret(userSecret) : "",
      });
    }();
    // migrate from sqlcipher 3 to 4
    db->execute("PRAGMA cipher_migrate");
    // enable foreign key support
    db->execute("PRAGMA foreign_keys = ON");
    // for revocation (when wiping db)
    db->execute("PRAGMA secure_delete = ON");

    // migrate from clear to encrypted db
    if (shouldMigrate)
    {
      auto const hexkey = hexUserSecret(userSecret);
      db->execute(fmt::format(
          R"(ATTACH DATABASE '{}.tmp' AS encrypted KEY "{}")", dbPath, hexkey));
      db->execute("SELECT sqlcipher_export('encrypted')");
      db->execute("DETACH DATABASE encrypted");
      db.reset();

      std::filesystem::rename(dbPath + ".tmp", dbPath);

      db = std::make_unique<Connection>(sqlpp::sqlite3::connection_config{
          dbPath.c_str(),
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
          "",
          false,
          hexkey});
    }

    {
      SCOPE_TIMER("finalize open", DB);
      // Check the open succeeded
      db->execute("SELECT count(*) FROM sqlite_master");
      if (exclusive)
        makeExclusive(db);
    }
    return db;
  }
  catch (sqlpp::exception const& e)
  {
    std::string const msg = e.what();
    if (msg.find("file is not a database") != std::string::npos)
      throw Errors::Exception(
          Errc::DatabaseCorrupt,
          "database is corrupted, or an incorrect identity was used");
    else if (msg.find("database is locked") != std::string::npos)
      throw Errors::Exception(Errc::DatabaseLocked,
                              "database is locked by another Tanker instance");
    else
      throw Errors::Exception(Errc::DatabaseError, e.what());
  }
  catch (std::exception const& e)
  {
    throw Errors::formatEx(Errors::Errc::InternalError,
                           FMT_STRING("could not open database: {:s}: {:s}"),
                           dbPath,
                           e.what());
  }
}
}
}
