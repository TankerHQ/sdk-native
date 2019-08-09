#include <Tanker/FileKit/DownloadStream.hpp>

#include <Tanker/Errors/Exception.hpp>

#include <boost/algorithm/string.hpp>

namespace Tanker
{
namespace FileKit
{
DownloadStream::DownloadStream(tccurl::multi& multi, std::string url)
  : _multi(multi), _url(std::move(url))
{
}

tc::cotask<int64_t> DownloadStream::operator()(uint8_t* out, int64_t size)
{
  if (_currentPosition == static_cast<int64_t>(_currentBuffer.size()))
  {
    if (_lastBuffer)
      TC_RETURN(0);
    TC_AWAIT(refill());
  }

  auto const toRead =
      std::min<int64_t>(_currentBuffer.size() - _currentPosition, size);
  std::copy_n(_currentBuffer.data() + _currentPosition, toRead, out);
  _currentPosition += toRead;
  TC_RETURN(toRead);
}

tc::cotask<void> DownloadStream::refill()
{
  assert(!_lastBuffer);

  auto const req = std::make_shared<tccurl::request>();
  req->set_url(_url);
  req->add_header(fmt::format(
      "range: bytes={}-{}", _position, _position + 1024 * 1024 - 1));

  auto result = TC_AWAIT(tccurl::read_all(_multi, req));
  handleResponse(*req, result);

  _currentBuffer = std::move(result.data);
  _currentPosition = 0;

  _position += _currentBuffer.size();

  if (_position >= _totalLength)
    _lastBuffer = true;
}

void DownloadStream::handleResponse(tccurl::request& req,
                                    tccurl::read_all_result const& result)
{
  if (!req.is_response_ok())
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status for download GET request: {}",
                           req.get_status_code());

  if (_totalLength == -1)
  {
    if (req.get_status_code() == 206)
    {
      auto const contentRangeIt = result.header.find("content-range");
      if (contentRangeIt == result.header.end())
        throw Errors::Exception(
            make_error_code(Errors::Errc::NetworkError),
            "missing content-range header for 206 (partial content) response");
      auto const& contentRange = contentRangeIt->second;
      auto const slashPos = contentRange.find('/');
      if (!boost::algorithm::starts_with(contentRange, "bytes ") ||
          slashPos == std::string::npos)
        throw Errors::formatEx(Errors::Errc::NetworkError,
                               "invalid content-range header: {}",
                               contentRange);
      _totalLength = std::stol(contentRange.substr(slashPos + 1));
    }
    else
      _totalLength = result.data.size();
  }
}
}
}
