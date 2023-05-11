#include <catch2/catch_test_macros.hpp>

#include <tconcurrent/async.hpp>
#include <tconcurrent/async_wait.hpp>
#include <tconcurrent/promise.hpp>

#include <tcurl.hpp>

using namespace tconcurrent;
using namespace tcurl;

TEST_CASE("curl simple request")
{
  multi mul;

  promise<CURLcode> finished;
  long httpcode = 0;
  long expectedhttpcode = 0;
  bool dataread = false;
  auto req = std::make_shared<request>();
  req->set_read_callback([&](request& r, void const*, std::size_t size) {
    curl_easy_getinfo(r.get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
    dataread = true;
    return size;
  });
  req->set_finish_callback(
      [=](request&, CURLcode c) mutable { finished.set_value(c); });

  SECTION("http")
  {
    expectedhttpcode = 200;
    req->set_url("http://httpbingo.org/get?TEST=test");
  }

  SECTION("https")
  {
    expectedhttpcode = 200;
    req->set_url("https://httpbingo.org/get?TEST=test");
  }

  SECTION("not found")
  {
    expectedhttpcode = 404;
    req->set_url("http://httpbingo.org/whatever");
  }

  SECTION("post")
  {
    expectedhttpcode = 200;
    req->set_url("http://httpbingo.org/post");
    static char const buf[] = "Test test test";
    curl_easy_setopt(req->get_curl(), CURLOPT_POST, 1l);
    curl_easy_setopt(
        req->get_curl(), CURLOPT_POSTFIELDSIZE, long(sizeof(buf) - 1));
    curl_easy_setopt(req->get_curl(), CURLOPT_POSTFIELDS, buf);
  }

  mul.process(req);
  auto code = finished.get_future().get();
  auto err = curl_easy_strerror(code);
  CAPTURE(err);
  CHECK(CURLE_OK == code);
  CHECK(dataread);
  CHECK(expectedhttpcode == httpcode);
}

TEST_CASE("curl cancel request")
{
  multi mul;

  auto req = std::make_shared<request>();
  req->set_read_callback(
      [](request&, void const*, std::size_t size) { return size; });
  req->set_finish_callback([](request&, CURLcode c) { CHECK(false); });
  req->set_url("http://httpbingo.org/delay/10");

  auto before = std::chrono::steady_clock::now();
  mul.process(req);
  async([&] { mul.cancel(*req); }).get();
  auto after = std::chrono::steady_clock::now();

  CHECK(std::chrono::seconds(1) > after - before);
}

TEST_CASE("curl destroy multi during request")
{
  auto mul = new multi;

  auto req = std::make_shared<request>();
  req->set_read_callback(
      [](request&, void const*, std::size_t size) { return size; });
  req->set_finish_callback([](request&, CURLcode c) { CHECK(false); });
  req->set_url("http://httpbingo.org/delay/5");

  mul->process(req);

  tc::async_wait(std::chrono::milliseconds(100))
      .then([&](tc::future<void> const&) { delete mul; })
      .get();
}

TEST_CASE("curl multiple requests")
{
  static auto const NB = 5;

  multi mul;

  promise<void> finished[NB];
  bool dataread[NB] = {false};
  std::shared_ptr<request> reqs[NB];
  for (auto& req : reqs)
    req = std::make_shared<request>();

  for (int i = 0; i < NB; ++i)
  {
    reqs[i]->set_read_callback(
        [&dataread, i](request&, void const*, std::size_t size) {
          dataread[i] = true;
          return size;
        });
    promise<void> finish = finished[i];
    reqs[i]->set_finish_callback(
        [finish](request&, CURLcode) mutable { finish.set_value({}); });
    reqs[i]->set_url("http://httpbingo.org/drip?numbytes=100&duration=1");
  }

  for (int i = 0; i < NB; ++i)
    mul.process(reqs[i]);

  for (int i = 0; i < NB; ++i)
  {
    finished[i].get_future().wait();
    CHECK(dataread[i]);
  }
}

#define CHECK_READALL()                                                  \
  auto fut = read_all(mul, req);                                         \
                                                                         \
  auto result = fut.get();                                               \
  long httpcode;                                                         \
  curl_easy_getinfo(req->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode); \
                                                                         \
  CHECK(200 == httpcode);                                                \
  CHECK(!result.data.empty());

TEST_CASE("curl failure")
{
  multi mul;
  auto req = std::make_shared<request>();

  req->set_url("/lol");

  auto fut = read_all(mul, req);
  fut.wait();
  CHECK(fut.has_exception());
}

TEST_CASE("curl read_all")
{
  multi mul;
  auto req = std::make_shared<request>();

  SECTION("simple")
  {
    req->set_url("http://httpbingo.org/get?TEST=test");
    CHECK_READALL()
  }

  SECTION("post continue")
  {
    req->set_url("http://httpbingo.org/post");
    static char const buf[] = "Test test test";
    curl_easy_setopt(req->get_curl(), CURLOPT_POST, 1l);
    curl_easy_setopt(
        req->get_curl(), CURLOPT_POSTFIELDSIZE, long(sizeof(buf) - 1));
    curl_easy_setopt(req->get_curl(), CURLOPT_POSTFIELDS, buf);
    req->add_header("Expect: 100-continue");
    CHECK_READALL()
  }
}

TEST_CASE("curl read_all cancel")
{
  multi mul;
  auto req = std::make_shared<request>();
  req->set_url("http://httpbingo.org/delay/10");

  auto fut = read_all(mul, req);
  async([&] { fut.request_cancel(); }).get();
  auto before = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(fut.get(), operation_canceled);
  auto after = std::chrono::steady_clock::now();

  CHECK(std::chrono::seconds(1) > after - before);
}

TEST_CASE("curl read_all destroy multi")
{
  auto mul = std::make_unique<multi>();

  auto req = std::make_shared<request>();
  req->set_url("http://httpbingo.org/delay/10");
  auto fut = read_all(*mul, req);
  async([&] { mul.reset(); }).get();
  auto before = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(fut.get(), operation_canceled);
  auto after = std::chrono::steady_clock::now();

  CHECK(std::chrono::seconds(1) > after - before);
}
