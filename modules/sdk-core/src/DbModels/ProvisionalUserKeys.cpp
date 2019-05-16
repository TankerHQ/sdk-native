#include <Tanker/DbModels/ProvisionalUserKeys.hpp>

#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Log.hpp>

TLOG_CATEGORY(provisional_user_keys);

namespace Tanker
{
namespace DbModels
{
namespace provisional_user_keys
{
void createTable(DataStore::Connection& db, provisional_user_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS provisional_user_keys (
      app_pub_sig_key BLOB NOT NULL,
      tanker_pub_sig_key BLOB NOT NULL,
      app_enc_pub BLOB NOT NULL,
      app_enc_priv BLOB NOT NULL,
      tanker_enc_pub BLOB NOT NULL,
      tanker_enc_priv BLOB NOT NULL,
      PRIMARY KEY (app_pub_sig_key, tanker_pub_sig_key)
    );
  )");
}
}
}
}
