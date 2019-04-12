#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Crypto/Types.hpp>

#include <optional.hpp>
#include <sqlpp11/sqlite3/connection.h>

#include <memory>
#include <string>

namespace Tanker
{

namespace DataStore
{
using Connection = sqlpp::sqlite3::connection;
using ConnPtr = std::unique_ptr<sqlpp::sqlite3::connection>;

ConnPtr createConnection(std::string const& dbPath,
                         nonstd::optional<Crypto::SymmetricKey> userSecret = {},
                         bool exclusive = true);

constexpr bool hasCipher()
{
  return
#ifdef SQLCIPHER_CRYPTO_OPENSSL
      true
#else
      false
#endif
      ;
}
}
}
