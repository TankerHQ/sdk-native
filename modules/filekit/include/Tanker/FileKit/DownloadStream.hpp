#pragma once

#include <tccurl/curl.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <string>

namespace Tanker
{
namespace FileKit
{
class DownloadStream
{
public:
  DownloadStream(tccurl::multi& multi, std::string url);

  tc::cotask<int64_t> operator()(uint8_t* out, int64_t size);

private:
  tccurl::multi& _multi;
  std::string _url;
  int64_t _totalLength = -1;
  int64_t _position = 0;
  bool _lastBuffer = false;

  std::vector<uint8_t> _currentBuffer;
  int64_t _currentPosition = 0;

  tc::cotask<void> refill();

  void handleResponse(tccurl::request& req,
                      tccurl::read_all_result const& result);
};
}
}
