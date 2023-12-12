#pragma once

#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/DataStore/Connection.hpp>

namespace Tanker::DataStore
{
inline constexpr auto MemoryPath = ":memory:";

class SqliteBackend : public Backend
{
public:
  std::unique_ptr<DataStore> open(std::string const& dataPath, std::string const& cachePath) override;
};

class SqliteDataStore : public DataStore
{
public:
  void nuke() override;

  void putSerializedDevice(gsl::span<uint8_t const> device) override;
  std::optional<std::vector<uint8_t>> findSerializedDevice() override;

  void putCacheValues(gsl::span<std::pair<Key, Value> const> keyValues, OnConflict onConflict) override;
  std::vector<std::optional<std::vector<uint8_t>>> findCacheValues(gsl::span<Key const> keys) override;

private:
  ConnPtr _dbDevice;
  ConnPtr _dbCache;

  SqliteDataStore(ConnPtr dbDevice, ConnPtr dbCache);

  friend class SqliteBackend;
};
}
