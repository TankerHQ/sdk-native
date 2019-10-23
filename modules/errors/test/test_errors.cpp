#include <Tanker/Errors/Errc.hpp>

#include <doctest.h>
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
