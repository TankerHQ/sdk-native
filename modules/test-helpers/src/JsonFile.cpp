#include <Helpers/JsonFile.hpp>

#include <nlohmann/json.hpp>

#include <fstream>

namespace Tanker
{
nlohmann::json loadJson(std::string const& src)
{
  std::ifstream ifs(src);

  return nlohmann::json::parse(ifs);
}

void saveJson(std::string const& dest, nlohmann::json const& json)
{
  std::ofstream ofs(dest, std::ios::trunc);
  auto dump = json.dump();
  ofs.write(dump.data(), dump.size());
}
}
