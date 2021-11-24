#pragma once

#include <Tanker/Network/Backend.hpp>

#include <ctanker/network.h>

class CTankerBackend : public Tanker::Network::Backend
{
public:
  CTankerBackend(tanker_http_options_t const& options);

  tc::cotask<Tanker::Network::HttpResponse> fetch(
      Tanker::Network::HttpRequest req) override;

private:
  tanker_http_options_t _options;
};
