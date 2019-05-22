#include <Tanker/Errors/Errc.hpp>

#include <ostream>
#include <doctest.h>

using namespace Tanker::Errors;

TEST_CASE("Errc")
{
  SUBCASE("Conversion to std::error_condition")
  {
    std::error_condition ec = Errc::InvalidArgument;

    CHECK_EQ(ec, Errc::InvalidArgument);
  }

  SUBCASE("std::error_code creation")
  {
    auto const ec = make_error_code(Errc::OperationCanceled);
    CHECK_EQ(ec, Errc::OperationCanceled);
  }
}
