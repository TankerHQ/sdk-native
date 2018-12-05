#pragma once

#include <Helpers/Config.hpp>
#include <tanker.h>

using namespace Tanker;

class TestTrustchain
{
public:
  TestTrustchain(
      std::string trustchainUrl = Tanker::TestConstants::trustchainUrl())
    : _trustchainUrl(std::move(trustchainUrl))
  {
    tanker_future_t* admin_fut = tanker_admin_connect(
        _trustchainUrl.c_str(), Tanker::TestConstants::idToken().c_str());
    tanker_future_wait(admin_fut);
    if (tanker_future_has_error(admin_fut))
      throw std::runtime_error(tanker_future_get_error(admin_fut)->message);
    _admin = (tanker_admin_t*)tanker_future_get_voidptr(admin_fut);
    tanker_future_destroy(admin_fut);

    tanker_future_t* trustchain_fut =
        tanker_admin_create_trustchain(_admin, "functest-c");
    tanker_future_wait(trustchain_fut);
    if (tanker_future_has_error(trustchain_fut))
      throw std::runtime_error(
          tanker_future_get_error(trustchain_fut)->message);
    _trustchain = (tanker_trustchain_descriptor_t*)tanker_future_get_voidptr(
        trustchain_fut);
    tanker_future_destroy(trustchain_fut);
  }

  ~TestTrustchain()
  {
    tanker_future_t* future_delete_trustchain =
        tanker_admin_delete_trustchain(_admin, _trustchain->id);
    tanker_future_wait(future_delete_trustchain);
    tanker_future_destroy(future_delete_trustchain);
    tanker_admin_trustchain_descriptor_free(_trustchain);

    tanker_future_t* future_admin_destroy = tanker_admin_destroy(_admin);
    tanker_future_wait(future_admin_destroy);
    tanker_future_destroy(future_admin_destroy);
  }

  auto url() const
  {
    return _trustchainUrl.c_str();
  }

  auto id() const
  {
    return _trustchain->id;
  }

  auto privateKey() const
  {
    return _trustchain->private_key;
  }

private:
  std::string _trustchainUrl;
  tanker_admin_t* _admin;
  tanker_trustchain_descriptor_t* _trustchain;
};
