#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <doctest.h>

#include <ostream>
#include <string>
#include <vector>

namespace
{
struct CustomType
{
  int value;
};

bool operator==(CustomType const& lhs, CustomType const& rhs)
{
  return lhs.value == rhs.value;
}

class PreprocessorTest
{
  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(PreprocessorTest,
                                          (string, std::string),
                                          (vector, std::vector<int>),
                                          (custom, CustomType))
};
}

TEST_CASE("Preprocessor tests")
{
  SUBCASE("Action implementation")
  {
    PreprocessorTest pt{"test", {0, 1, 2}, {42}};
    PreprocessorTest pt2{"tes", {0, 1, 2}, {42}};

    CHECK(pt.string() == "test");
    CHECK(pt.vector() == std::vector<int>{0, 1, 2});
    CHECK(pt.custom().value == 42);
    CHECK(pt == pt);
    CHECK(pt != pt2);
  }
}
