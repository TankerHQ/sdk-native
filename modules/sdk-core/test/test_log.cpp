#include <catch2/catch.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <Helpers/Buffers.hpp>

#include <mgs/base64.hpp>

#include <iostream>

using Tanker::Trustchain::Actions::Nature;

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

  SECTION("Print a log")
  {
    TLOG(Info, "this a log");
    TLOG(Info, "this a '{:^26s}' log", "formatted");
  }

  SECTION("Set a loghandler")
  {
    Tanker::Log::setLogHandler(&myLogHandler);
    TINFO("I am the message");
  }

  SECTION("Reset a LogHandler")
  {
    Tanker::Log::setLogHandler(&myLogHandler);
    TINFO("I am the message");
    Tanker::Log::setLogHandler(nullptr);
    TINFO("I am the message no handler");
  }

  SECTION("Print a simple info")
  {
    TINFO("didn't find the error");
  }

  SECTION("Print a formated info")
  {
    TINFO(
        "didn't find the error {0}!, "
        "with {1:+02d}, "
        "and {2:.3f} '{0:^6s}'",
        "wat",
        42,
        1.4);
  }

  SECTION("Print a status")
  {
    CHECK(fmt::format("this is is a Status {:e}", Tanker::Status::Ready) ==
          R"!(this is is a Status 1 Ready)!");
    CHECK(fmt::format("this is is a Status {}", Tanker::Status::Ready) ==
          R"!(this is is a Status 1 Ready)!");
  }

  SECTION("Print a Nature")
  {
    CHECK(fmt::format("this is is a Nature {:e}", Nature::KeyPublishToUser) ==
          R"!(this is is a Nature 8 KeyPublishToUser)!");
  }

  SECTION("Print the fear")
  {
    TERROR("This is bad");
  }

  SECTION("It format a ResourceId")
  {
    auto resourceId =
        Tanker::make<Tanker::Trustchain::ResourceId>("awesome, isn't it?");
    REQUIRE(
        fmt::format("my resourceId is {}", mgs::base64::encode(resourceId)) ==
        fmt::format("my resourceId is {}", resourceId));
  }
}
