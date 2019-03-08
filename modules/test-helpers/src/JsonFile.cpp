#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/string_file.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
nlohmann::json loadJson(std::string const& src)
{
  std::string content;
  boost::filesystem::load_string_file(src, content);
  return nlohmann::json::parse(content);
}

void saveJson(std::string const& dest, nlohmann::json const& json)
{
  boost::filesystem::save_string_file(dest, json.dump());
}
}
