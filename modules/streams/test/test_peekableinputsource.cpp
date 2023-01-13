#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Streams/Helpers.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace Tanker;
using namespace Tanker::Errors;
using namespace Tanker::Streams;

namespace
{
auto fillAndMakePeekableSource(std::vector<uint8_t>& buffer)
{
  Crypto::randomFill(buffer);
  auto source = bufferViewToInputSource(buffer);
  return PeekableInputSource(source);
}
}

TEST_CASE("reads an underlying stream", "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(50);
  auto peekable = fillAndMakePeekableSource(buffer);

  auto out = AWAIT(readAllStream(peekable));
  CHECK(out == buffer);
}

TEST_CASE("peeks and reads an underlying stream", "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(50);
  auto peekable = fillAndMakePeekableSource(buffer);

  auto peek = AWAIT(peekable.peek(30));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 30));

  auto out = AWAIT(readAllStream(peekable));
  CHECK(out == buffer);
}

TEST_CASE("peeks past the end and reads an underlying stream",
          "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(50);
  auto peekable = fillAndMakePeekableSource(buffer);

  auto peek = AWAIT(peekable.peek(70));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 50));

  auto out = AWAIT(readAllStream(peekable));
  CHECK(out == buffer);
}

TEST_CASE("peek multiple times", "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(50);
  auto peekable = fillAndMakePeekableSource(buffer);

  auto peek = AWAIT(peekable.peek(30));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 30));

  peek = AWAIT(peekable.peek(10));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 10));

  peek = AWAIT(peekable.peek(40));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 40));

  peek = AWAIT(peekable.peek(100));
  // We reached the end of the buffer, so fewer bytes are available
  CHECK(peek == gsl::make_span(buffer).subspan(0, 50));
}

TEST_CASE("peek multiple times with a pre-filled peeking buffer",
          "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(50);
  auto peekable = fillAndMakePeekableSource(buffer);

  AWAIT(peekable.peek(10));
  {
    std::vector<uint8_t> toRead(5);
    AWAIT(peekable(toRead));
  }

  auto peek = AWAIT(peekable.peek(30));
  CHECK(peek == gsl::make_span(buffer).subspan(5, 30));

  peek = AWAIT(peekable.peek(10));
  CHECK(peek == gsl::make_span(buffer).subspan(5, 10));

  peek = AWAIT(peekable.peek(40));
  CHECK(peek == gsl::make_span(buffer).subspan(5, 40));

  peek = AWAIT(peekable.peek(100));
  // We reached the end of the buffer, so fewer bytes are available
  CHECK(peek == gsl::make_span(buffer).subspan(5, 45));
}

TEST_CASE("alternate between peeks and read on a long underlying stream",
          "[peekableinputsource]")
{
  std::vector<uint8_t> buffer(5 * 1024 * 1024);
  auto peekable = fillAndMakePeekableSource(buffer);

  auto peek = AWAIT(peekable.peek(30));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 30));

  peek = AWAIT(peekable.peek(1200));
  CHECK(peek == gsl::make_span(buffer).subspan(0, 1200));

  std::vector<uint8_t> begin(1000);
  AWAIT(readStream(begin, peekable));
  CHECK(gsl::make_span(begin) == gsl::make_span(buffer).subspan(0, 1000));

  peek = AWAIT(peekable.peek(10));
  CHECK(peek == gsl::make_span(buffer).subspan(1000, 10));

  auto out = AWAIT(readAllStream(peekable));
  CHECK(gsl::make_span(out) == gsl::make_span(buffer).subspan(1000));
}
