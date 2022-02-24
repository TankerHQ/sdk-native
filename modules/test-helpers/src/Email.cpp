#include <Helpers/Email.hpp>
#include <random>

namespace Tanker
{
auto makeEmail(int size) -> Email
{
  std::mt19937_64 gen{std::random_device{}()};
  std::uniform_int_distribution<short> dist{'a', 'z'};

  std::string str(size, '\0');
  for (auto& c : str)
  {
    c = dist(gen);
  }

  return Email{fmt::format("{:s}@doctolib.com", str)};
}
}
