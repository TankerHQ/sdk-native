#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>

#include <doctest.h>

#include <cstddef>
#include <ostream>
#include <string>
#include <vector>

namespace
{
struct CustomType
{
  char value;

  char const& front() const
  {
    return value;
  }

  char const& back() const
  {
    return value;
  }
};

bool operator==(CustomType const& lhs, CustomType const& rhs)
{
  return lhs.value == rhs.value;
}

class PreprocessorTest
{
  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(PreprocessorTest,
                                          (string, std::string),
                                          (vector, std::vector<char>),
                                          (custom, CustomType))
};

class VariantTest
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(VariantTest,
                                                  (std::string,
                                                   std::vector<char>,
                                                   CustomType),
                                                  (front, char),
                                                  (back, char))
};
}

TEST_CASE("Preprocessor tests")
{
  SUBCASE("Action implementation")
  {
    PreprocessorTest pt{"test", {0, 1, 2}, {42}};
    PreprocessorTest pt2{"tes", {0, 1, 2}, {42}};

    CHECK(pt.string() == "test");
    CHECK(pt.vector() == std::vector<char>{0, 1, 2});
    CHECK(pt.custom().value == 42);
    CHECK(pt == pt);
    CHECK(pt != pt2);
  }

  SUBCASE("Action variant implementation")
  {
    VariantTest vt{CustomType{42}};
    VariantTest vt2{std::vector<char>{42}};

    CHECK(vt.front() == 42);
    CHECK(vt.holdsAlternative<CustomType>());
    CHECK(vt2.front() == 42);
    CHECK(vt != vt2);
  }
}
