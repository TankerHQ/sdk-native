#include <ctanker/datastore.h>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <ctanker/private/CDataStore.hpp>
#include <ctanker/private/Utils.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/promise.hpp>

#include <range/v3/view/iota.hpp>
#include <range/v3/view/map.hpp>

TLOG_CATEGORY(CTankerStorage);

using namespace Tanker::DataStore;
namespace Errors = Tanker::Errors;

std::unique_ptr<Tanker::DataStore::Backend> extractStorageBackend(
    tanker_datastore_options_t const& options)
{
  auto const datastoreHandlersCount =
      !!options.open + !!options.close + !!options.nuke +
      !!options.put_serialized_device + !!options.find_serialized_device +
      !!options.put_cache_values + !!options.find_cache_values;
  if (datastoreHandlersCount != 0 && datastoreHandlersCount != 7)
    throw Errors::Exception(
        make_error_code(Errors::Errc::InternalError),
        "the provided datastore implementation is incomplete");
  if (datastoreHandlersCount == 0)
    return nullptr;
  return std::make_unique<CTankerStorageBackend>(options);
}

#define STATIC_ENUM_CHECK(cval, cppval)           \
  static_assert(cval == static_cast<int>(cppval), \
                "enum values not in sync: " #cval " and " #cppval)

STATIC_ENUM_CHECK(TANKER_DATASTORE_ONCONFLICT_FAIL, OnConflict::Fail);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ONCONFLICT_IGNORE, OnConflict::Ignore);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ONCONFLICT_REPLACE, OnConflict::Replace);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ONCONFLICT_LAST, OnConflict::Last);

static_assert(TANKER_DATASTORE_ONCONFLICT_LAST == 3,
              "Please update the assertions above if you added a new "
              "onconflict method");

STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_INVALID_DATABASE_VERSION,
                  Errc::InvalidDatabaseVersion);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_RECORD_NOT_FOUND,
                  Errc::RecordNotFound);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_DATABASE_ERROR, Errc::DatabaseError);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_DATABASE_LOCKED, Errc::DatabaseLocked);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_DATABASE_CORRUPT,
                  Errc::DatabaseCorrupt);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_DATABASE_TOO_RECENT,
                  Errc::DatabaseTooRecent);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_CONSTRAINT_FAILED,
                  Errc::ConstraintFailed);
STATIC_ENUM_CHECK(TANKER_DATASTORE_ERROR_LAST, Errc::Last);

static_assert(TANKER_DATASTORE_ERROR_LAST == 8,
              "Please update the assertions above if you added a new "
              "datastore error");

#undef STATIC_ENUM_CHECK

namespace
{
void rethrowError(std::exception_ptr e)
{
  if (e)
    std::rethrow_exception(e);
}
}

CTankerStorageBackend::CTankerStorageBackend(
    tanker_datastore_options_t const& options)
  : _options(options)
{
}

std::unique_ptr<DataStore> CTankerStorageBackend::open(
    std::string const& dataPath, std::string const& cachePath)
{
  tanker_datastore_t* db;
  std::exception_ptr err;
  TDEBUG("Opening databases {} and {}", dataPath, cachePath);
  tc::dispatch_on_thread_context([&] {
    return _options.open(&err, &db, dataPath.c_str(), cachePath.c_str());
  });
  rethrowError(err);
  return std::make_unique<CTankerStorageDataStore>(_options, db);
}

CTankerStorageDataStore::CTankerStorageDataStore(
    tanker_datastore_options_t options, tanker_datastore_t* store)
  : _options(options), _datastore(store)
{
  TDEBUG("Opened database ({})", static_cast<void*>(this));
}

CTankerStorageDataStore::~CTankerStorageDataStore()
{
  TDEBUG("Closing databases ({})", static_cast<void*>(this));
  tc::dispatch_on_thread_context([&] { _options.close(_datastore); });
}

void CTankerStorageDataStore::nuke()
{
  std::exception_ptr err;
  tc::dispatch_on_thread_context(
      [&] { return _options.nuke(_datastore, &err); });
  rethrowError(err);
}

void CTankerStorageDataStore::putSerializedDevice(
    gsl::span<uint8_t const> device)
{
  std::exception_ptr err;
  tc::dispatch_on_thread_context([&] {
    return _options.put_serialized_device(
        _datastore, &err, device.data(), device.size());
  });
  rethrowError(err);
}

namespace
{
struct DeviceResult
{
  std::exception_ptr err;
  std::optional<std::vector<uint8_t>> data;
};
}

std::optional<std::vector<uint8_t>>
CTankerStorageDataStore::findSerializedDevice()
{
  DeviceResult result;
  tc::dispatch_on_thread_context(
      [&] { return _options.find_serialized_device(_datastore, &result); });
  rethrowError(result.err);
  return result.data;
}

uint8_t* tanker_datastore_allocate_device_buffer(
    tanker_datastore_device_get_result_handle_t* result_handle, uint32_t size)
{
  auto& optVec = static_cast<DeviceResult*>(result_handle)->data;
  optVec = std::vector<uint8_t>(size);
  return optVec->data();
}

void CTankerStorageDataStore::putCacheValues(
    gsl::span<std::pair<Key, Value> const> keyValues, OnConflict onConflict)
{
  auto const keyPtrs = keyValues | ranges::views::keys |
                       ranges::views::transform(&Key::data) |
                       ranges::to<std::vector>;
  auto const keySizes = keyValues | ranges::views::keys |
                        ranges::views::transform(&Key::size) |
                        ranges::to<std::vector<uint32_t>>;
  auto const valuePtrs = keyValues | ranges::views::values |
                         ranges::views::transform(&Value::data) |
                         ranges::to<std::vector>;
  auto const valueSizes = keyValues | ranges::views::values |
                          ranges::views::transform(&Value::size) |
                          ranges::to<std::vector<uint32_t>>;

  std::exception_ptr err;
  tc::dispatch_on_thread_context([&] {
    return _options.put_cache_values(_datastore,
                                     &err,
                                     keyPtrs.data(),
                                     keySizes.data(),
                                     valuePtrs.data(),
                                     valueSizes.data(),
                                     keyValues.size(),
                                     static_cast<uint8_t>(onConflict));
  });
  rethrowError(err);
}

namespace
{
struct CacheResult
{
  std::exception_ptr err;
  std::vector<std::optional<std::vector<uint8_t>>> data;
};
}

std::vector<std::optional<std::vector<uint8_t>>>
CTankerStorageDataStore::findCacheValues(
    gsl::span<gsl::span<uint8_t const> const> keys)
{
  std::vector<uint8_t const*> keyPtrs;
  std::vector<uint32_t> keySizes;
  keyPtrs.reserve(keys.size());
  keySizes.reserve(keys.size());
  for (auto const& kv : keys)
  {
    keyPtrs.push_back(kv.data());
    keySizes.push_back(kv.size());
  }

  CacheResult result;
  result.data.resize(keys.size());
  tc::dispatch_on_thread_context([&] {
    return _options.find_cache_values(
        _datastore, &result, keyPtrs.data(), keySizes.data(), keys.size());
  });
  rethrowError(result.err);
  if (result.data.size() != keys.size())
    throw Errors::formatEx(Errc::DatabaseError,
                           "the database backend didn't return enough results");

  return result.data;
}

void tanker_datastore_allocate_cache_buffer(
    tanker_datastore_cache_get_result_handle_t* result_handle,
    uint8_t** outPtrs,
    uint32_t* sizes)
{
  auto& vec = static_cast<CacheResult*>(result_handle)->data;
  for (auto i : ranges::views::iota(0u, vec.size()))
  {
    if (sizes[i] != TANKER_DATASTORE_ALLOCATION_NONE)
    {
      auto& row = vec.at(i);
      row.emplace(sizes[i]);
      outPtrs[i] = row->data();
    }
  }
}

void tanker_datastore_report_error(tanker_datastore_error_handle_t* handle,
                                   uint8_t error_code,
                                   char const* message)
{
  auto const err = static_cast<std::exception_ptr*>(handle);
  *err = std::make_exception_ptr(
      Errors::formatEx(static_cast<Errc>(error_code), "{}", message));
}
