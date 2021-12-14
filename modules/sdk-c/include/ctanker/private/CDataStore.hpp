#pragma once

#include <Tanker/DataStore/Backend.hpp>

#include <ctanker/datastore.h>

class CTankerStorageBackend : public Tanker::DataStore::Backend
{
public:
  CTankerStorageBackend(tanker_datastore_options_t const& options);

  std::unique_ptr<Tanker::DataStore::DataStore> open(
      std::string const& dataPath, std::string const& cachePath) override;

private:
  tanker_datastore_options_t _options;
};

class CTankerStorageDataStore : public Tanker::DataStore::DataStore
{
public:
  CTankerStorageDataStore(tanker_datastore_options_t options,
                          tanker_datastore_t* store);
  ~CTankerStorageDataStore();

  void nuke() override;

  void putSerializedDevice(gsl::span<uint8_t const> device) override;
  std::optional<std::vector<uint8_t>> findSerializedDevice() override;

  void putCacheValues(gsl::span<std::pair<Key, Value> const> keyValues,
                      Tanker::DataStore::OnConflict onConflict) override;
  std::vector<std::optional<std::vector<uint8_t>>> findCacheValues(
      gsl::span<Key const> keys) override;

private:
  tanker_datastore_options_t _options;

  tanker_datastore_t* _datastore;
};

std::unique_ptr<Tanker::DataStore::Backend> extractStorageBackend(
    tanker_datastore_options_t const& options);
