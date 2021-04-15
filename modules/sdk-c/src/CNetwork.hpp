#pragma once

#include <Tanker/Network/Backend.hpp>

#include <ctanker/network.h>

class CTankerBackend : public Tanker::Network::Backend
{
public:
  CTankerBackend(tanker_http_send_request_t cfetch,
                 tanker_http_cancel_request_t ccancel,
                 void* cdata);

  tc::cotask<Tanker::Network::HttpResponse> fetch(
      Tanker::Network::HttpRequest req) override;

private:
  tanker_http_send_request_t _cfetch;
  tanker_http_cancel_request_t _ccancel;
  void* _cdata;
};
