#include <Tanker/Errors/Errc.hpp>

#include <catch2/catch.hpp>

using namespace Tanker::Errors;

TEST_CASE("Errors")
{
  SECTION("Errc")
  {
    {
      std::error_condition ec = Errc::InvalidArgument;
      CHECK(ec == Errc::InvalidArgument);
    }
    {
      auto const ec = make_error_code(Errc::OperationCanceled);
      CHECK(ec == Errc::OperationCanceled);
    }
  }
}
