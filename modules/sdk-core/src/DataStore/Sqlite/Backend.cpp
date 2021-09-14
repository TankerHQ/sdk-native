#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Utils.hpp>

#include <sqlpp11/ppgen.h>
#include <sqlpp11/sqlite3/insert_or.h>
#include <sqlpp11/sqlpp11.h>

#include <boost/container/flat_map.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

namespace Tanker::DataStore
{
namespace
{
constexpr auto LatestDeviceVersion = 1;
constexpr auto LatestCacheVersion = 1;

// clang-format off
SQLPP_DECLARE_TABLE(
  (device)
  ,
  (id                     , int  , SQLPP_PRIMARY_KEY )
  (deviceblob             , blob , SQLPP_NOT_NULL    )
)
SQLPP_DECLARE_TABLE(
  (cache)
  ,
  (key                    , blob , SQLPP_PRIMARY_KEY )
  (value                  , blob , SQLPP_NOT_NULL    )
)
// clang-format on

std::string appendDbSuffix(std::string db, std::string_view suffix)
{
  if (db != ":memory:")
    db.insert(db.end(), suffix.begin(), suffix.end());
  return db;
}

int getDbVersion(Connection& db)
{
  auto result = db(sqlpp::custom_query(sqlpp::verbatim("PRAGMA user_version"))
                       .with_result_type_of(
                           sqlpp::select(sqlpp::value(0).as(sqlpp::alias::a))));
  return result.begin()->a;
}

void createDeviceTable(Connection& db)
{
  db.execute(R"(
    CREATE TABLE device (
      id INTEGER PRIMARY KEY,
      deviceblob BLOB NOT NULL
    )
  )");
}

void createCacheTable(Connection& db)
{
  db.execute(R"(
    CREATE TABLE cache (
      key BLOB PRIMARY KEY,
      value BLOB NOT NULL
    )
  )");
}

ConnPtr openDeviceDb(std::string dataPath)
{
  auto dbDevice = createConnection(
      appendDbSuffix(std::move(dataPath), "-device.db"), {}, true);
  auto deviceVersion = getDbVersion(*dbDevice);
  switch (deviceVersion)
  {
  case 0:
    createDeviceTable(*dbDevice);
    dbDevice->execute(
        fmt::format("PRAGMA user_version = {}", LatestDeviceVersion));
    break;
  case LatestDeviceVersion:
    break;
  default:
    throw Errors::formatEx(
        Errc::DatabaseTooRecent,
        "device database version too recent, expected {}, got {}",
        LatestDeviceVersion,
        deviceVersion);
  }
  return dbDevice;
}

ConnPtr openCacheDb(std::string cachePath)
{
  auto dbCache = createConnection(
      appendDbSuffix(std::move(cachePath), "-cache.db"), {}, true);
  auto cacheVersion = getDbVersion(*dbCache);
  switch (cacheVersion)
  {
  case 0:
    createCacheTable(*dbCache);
    dbCache->execute(
        fmt::format("PRAGMA user_version = {}", LatestCacheVersion));
    break;
  case LatestCacheVersion:
    break;
  default:
    throw Errors::formatEx(
        Errc::DatabaseTooRecent,
        "cache database version too recent, expected {}, got {}",
        LatestCacheVersion,
        cacheVersion);
  }
  return dbCache;
}
}

using DeviceTable = device::device;
using CacheTable = cache::cache;

std::unique_ptr<DataStore> SqliteBackend::open(std::string const& dataPath,
                                               std::string const& cachePath)
{
  auto dbDevice = openDeviceDb(dataPath);
  auto dbCache = openCacheDb(cachePath);

  return std::unique_ptr<SqliteDataStore>(
      new SqliteDataStore(std::move(dbDevice), std::move(dbCache)));
}

SqliteDataStore::SqliteDataStore(ConnPtr dbDevice, ConnPtr dbCache)
  : _dbDevice(std::move(dbDevice)), _dbCache(std::move(dbCache))
{
}

void SqliteDataStore::nuke()
{
  DeviceTable deviceTable{};
  (*_dbDevice)(remove_from(deviceTable).unconditionally());
  CacheTable cacheTable{};
  (*_dbCache)(remove_from(cacheTable).unconditionally());
}

void SqliteDataStore::putSerializedDevice(gsl::span<uint8_t const> device)
{
  DeviceTable tab{};
  (*_dbDevice)(sqlpp::sqlite3::insert_or_replace_into(tab).set(
      tab.id = 1,
      tab.deviceblob = std::vector<uint8_t>(device.begin(), device.end())));
}

std::optional<std::vector<uint8_t>> SqliteDataStore::findSerializedDevice()
{
  DeviceTable tab{};
  auto rows = (*_dbDevice)(select(tab.deviceblob).from(tab).unconditionally());
  if (rows.empty())
    return std::nullopt;

  auto const& row = rows.front();
  return extractBlob<std::vector<uint8_t>>(row.deviceblob);
}

namespace
{
template <typename T>
void fillMultiInsert(
    T& multi_insert,
    gsl::span<std::pair<DataStore::Key, DataStore::Value> const> keyValues)
{
  CacheTable tab{};
  for (auto const& [key, value] : keyValues)
    multi_insert.values.add(tab.key = key | ranges::to<std::vector>,
                            tab.value = value | ranges::to<std::vector>);
}
}

void SqliteDataStore::putCacheValues(
    gsl::span<std::pair<Key, Value> const> keyValues, OnConflict onConflict)
{
  if (keyValues.empty())
    return;

  CacheTable tab{};

  switch (onConflict)
  {
  case OnConflict::Fail: {
    try
    {
      auto multi_insert = insert_into(tab).columns(tab.key, tab.value);
      fillMultiInsert(multi_insert, keyValues);
      (*_dbCache)(multi_insert);
    }
    catch (sqlpp::exception const& e)
    {
      std::string const msg = e.what();
      if (msg.find("UNIQUE constraint failed") != std::string::npos)
        throw Errors::formatEx(Errc::ConstraintFailed, "{}", msg);
      else
        throw;
    }
    return;
  }
  case OnConflict::Ignore: {
    auto multi_insert =
        sqlpp::sqlite3::insert_or_ignore_into(tab).columns(tab.key, tab.value);
    fillMultiInsert(multi_insert, keyValues);
    (*_dbCache)(multi_insert);
    return;
  }
  case OnConflict::Replace: {
    auto multi_insert =
        sqlpp::sqlite3::insert_or_replace_into(tab).columns(tab.key, tab.value);
    fillMultiInsert(multi_insert, keyValues);
    (*_dbCache)(multi_insert);
    return;
  }
  case OnConflict::Last:
    break;
  }
  throw Errors::formatEx(Errors::Errc::InternalError,
                         "unknown OnConflict value: {}",
                         static_cast<int>(onConflict));
}

namespace
{
template <typename T>
std::vector<std::optional<std::vector<uint8_t>>> sortResults(
    T& rows, std::vector<std::vector<uint8_t>> const& keys)
{
  boost::container::flat_map<std::vector<uint8_t>, std::vector<uint8_t>>
      resultMap;
  resultMap.reserve(keys.size());
  for (auto const& row : rows)
    resultMap[row.key] = extractBlob<std::vector<uint8_t>>(row.value);

  return keys |
         ranges::views::transform(
             [&](auto const& key) -> std::optional<std::vector<uint8_t>> {
               if (auto const it = resultMap.find(key); it != resultMap.end())
                 return it->second;
               else
                 return std::nullopt;
             }) |
         ranges::to<std::vector>;
}
}

std::vector<std::optional<std::vector<uint8_t>>>
SqliteDataStore::findCacheValues(
    gsl::span<gsl::span<uint8_t const> const> keysArg)
{
  // sqlpp needs vectors, so we convert the spans
  auto const keys = keysArg | ranges::views::transform([](auto const& k) {
                      return ranges::to<std::vector>(k);
                    }) |
                    ranges::to<std::vector>;

  CacheTable tab{};
  auto rows = (*_dbCache)(select(tab.key, tab.value)
                              .from(tab)
                              .where(tab.key.in(sqlpp::value_list(keys))));

  return sortResults(rows, keys);
}
}
