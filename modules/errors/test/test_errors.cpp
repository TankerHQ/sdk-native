#include <Tanker/Errors/Errc.hpp>

#include <doctest.h>
// VERY IMPORTANT to include this:
// https://github.com/onqtam/doctest/issues/183
#include <ostream>

using namespace Tanker::Errors;

TEST_CASE("Errors")
{
  SUBCASE("Errc")
  {
    {
      std::error_condition ec = Errc::InvalidArgument;
      CHECK_EQ(ec, Errc::InvalidArgument);
    }
    {
      auto const ec = make_error_code(Errc::OperationCanceled);
      CHECK_EQ(ec, Errc::OperationCanceled);
    }
  }
}
