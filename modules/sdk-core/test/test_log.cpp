#include <doctest.h>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/EnumFormat.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Status.hpp>

#include <Helpers/Buffers.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <iostream>

TLOG_CATEGORY(test);

namespace
{
void myLogHandler(Tanker::Log::Record const& s)
{
  std::cout << " this my log handler " << static_cast<std::uint32_t>(s.level)
            << " \"" << s.message << '"';
}
}

TEST_CASE("print a formated log")
{
  using namespace fmt::literals;
  std::string err = "this is a vary naughty error";
  Tanker::Log::setLogHandler(nullptr);

  SUBCASE("Print a log")
  {
    TLOG(Info, "this a log");
    TLOG(Info, "this a '{:^26s}' log", "formatted");
  }

  SUBCASE("Set a loghandler")
  {
    Tanker::Log::setLogHandler(&myLogHandler);
    TINFO("I am the message");
  }

  SUBCASE("Reset a LogHandler")
  {
    Tanker::Log::setLogHandler(&myLogHandler);
    TINFO("I am the message");
    Tanker::Log::setLogHandler(nullptr);
    TINFO("I am the message no handler");
  }

  SUBCASE("Print a simple info")
  {
    TINFO("didn't find the error");
  }

  SUBCASE("Print a formated info")
  {
    TINFO(
        "didn't find the error {0}!, "
        "with {1:+02d}, "
        "and {2:.3f} '{0:^6s}'",
        "wat",
        42,
        1.4);
  }

  SUBCASE("Print a status")
  {
    CHECK_EQ(fmt::format("this is is a Status {:e}", Tanker::Status::Open),
             R"!(this is is a Status 1 Open)!");
    CHECK_EQ(fmt::format("this is is a Status {}", Tanker::Status::Open),
             R"!(this is is a Status 1 Open)!");
  }

  SUBCASE("Print a Nature")
  {
    CHECK_EQ(fmt::format("this is is a Nature {:e}",
                         Tanker::Nature::KeyPublishToUser),
             R"!(this is is a Nature 8 KeyPublishToUser)!");
  }

  SUBCASE("Print the fear")
  {
    TERROR("This is bad");
  }

  SUBCASE("Throw an ex")
  {
    REQUIRE_THROWS(throw Tanker::Error::formatEx<std::runtime_error>(
        fmt("You lost, score {:d}/{:f}"), 42, 2.1));
  }

  SUBCASE("It format a Mac")
  {
    auto mac = Tanker::make<Tanker::Crypto::Mac>("awesome, isn't it?");
    REQUIRE(fmt::format("my mac is {}",
                        cppcodec::base64_rfc4648::encode(mac)) ==
            fmt::format("my mac is {}", mac));
  }
}
