#include <tcurl.hpp>

#include <boost/algorithm/string.hpp>

#include <tconcurrent/async.hpp>
#include <tconcurrent/promise.hpp>

namespace tcurl
{

namespace
{
struct read_all_helper
{
  multi& _multi;
  std::shared_ptr<request> _req;
  read_all_result::header_type _header;
  read_all_result::data_type _data;
  tc::promise<read_all_result> _promise;

  explicit read_all_helper(multi& multi) : _multi(multi)
  {
  }
};
}

tc::future<read_all_result> read_all(multi& multi, std::shared_ptr<request> req)
{
  auto ra = std::make_shared<read_all_helper>(multi);
  // creates a cycle, but it will be broken when the request finishes
  ra->_req = std::move(req);

  ra->_req->set_header_callback(
      [ra](request&, char const* data, std::size_t size) -> std::size_t {
        // for \r\n
        if (size < 2)
          return 0;

        if (size == 2)
          return size;

        // we may receive a response multiple times, for example for code
        // 100 Continue. I don't know if there are other examples of that
        if (size >= 4 && std::strncmp(data, "HTTP", 4) == 0 &&
            std::find(data, data + size, ':') == data + size)
          return size;

        // remove the \r\n
        size -= 2;

        auto const semicolon = std::find(data, data + size, ':');
        // incorrect header? take into account the space after the semi-colon
        if (semicolon + 2 > data + size)
          return 0;

        std::string key(data, semicolon);
        boost::algorithm::to_lower(key);
        ra->_header[std::move(key)] = std::string(semicolon + 2, data + size);

        return size + 2;
      });

  ra->_req->set_read_callback(
      [ra](request&, void const* data, std::size_t size) {
        auto u8data = static_cast<uint8_t const*>(data);
        ra->_data.insert(ra->_data.end(), u8data, u8data + size);
        return size;
      });

  ra->_req->set_finish_callback([ra](request&, CURLcode code) {
    if (code == CURLE_OK)
      ra->_promise.set_value(
          {ra->_req, std::move(ra->_header), std::move(ra->_data)});
    else
      ra->_promise.set_exception(std::make_exception_ptr(exception(code)));
    // break the cycles
    ra->_promise = {};
    ra->_req = nullptr;
  });

  ra->_req->set_abort_callback([ra](request&) {
    // if query is already finished
    if (!ra->_req)
      return;

    ra->_promise.set_exception(
        std::make_exception_ptr(tc::operation_canceled{}));
    // break the cycles
    ra->_promise = {};
    ra->_req = nullptr;
  });

  ra->_promise.get_cancelation_token().push_cancelation_callback([ra] {
    auto doCancel = [ra] {
      // if query is already finished
      if (!ra->_req)
        return;

      ra->_multi.cancel(*ra->_req);
      ra->_promise.set_exception(
          std::make_exception_ptr(tc::operation_canceled{}));
      ra->_promise = {};
      ra->_req = nullptr;
    };
    if (tc::get_default_executor().is_in_this_context())
      doCancel();
    else
      tc::async(doCancel);
  });

  // get the future first, the promise may be reset during the process
  auto fut = ra->_promise.get_future();

  multi.process(ra->_req);

  return fut;
}
}
