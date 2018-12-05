#include <boost/program_options.hpp>

#include <Generator/Generator.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Log.hpp>

#include <fmt/color.h>
#include <fmt/ostream.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iterator>

TLOG_CATEGORY(Generator);
namespace po = boost::program_options;

namespace TGen = Tanker::Generator;

using namespace std::string_literals;
using namespace Tanker::Generator::literals;

namespace
{
auto const defaultUrl = "https://dev-api.tanker.io"s;
auto const tokenId =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJodHRwczovL3Rhbmtlci1kYXNoYm9hcmQuZXUuYXV0aDAuY29tLyIsInN1YiI6Im"
    "F1dGgwfDVhODMxOGZhM2FmZjczMTAxMzI0YWM2YSIsImF1ZCI6ImxlY0liTzVDNk5TTGdRcHo4"
    "ZVVFRVpPMUpXbFB4ZUtKIiwiaWF0IjoxNTExNDUyMDIxLCJleHAiOjI1MzM3MDc2NDgwMCwibm"
    "9uY2UiOiJCQWItek9lckp1d3E1U29hY0JhNUgycUlIWkZxSUZjNCJ9."
    "zqVbGFssprvF40LZOtWcBp7onWEAdModBwu-jJO2q5M"s;

template <typename T>
T value_or(po::variable_value const& value, T const& def)
{
  return value.empty() ? def : value.as<T>();
}

bool dump(po::variable_value const& value, std::string const& json)
{
  if (value.defaulted())
    fmt::print(fmt::color::yellow, "the trustchain is \n{}\n", json);
  else if (!value.empty())
  {
    auto const filename = value.as<std::string>();
    auto file = std::ofstream(filename);
    if (!file.good())
    {
      fmt::print(fmt::color::red,
                 "Cannot open file '{}' to dump trustchain specs",
                 filename);
      return false;
    }
    file << json;
    file.close();
  }
  return true;
}

std::string trustchainInfos(TGen::Gen const& tc,
                            TGen::Devices const& users,
                            TGen::Devices const& ghs,
                            po::variable_value const& password,
                            TGen::Shares const& shares)
{
  auto tcInfos = nlohmann::json(tc);
  tcInfos["params"] = {{"nb_users", users.size()},
                       {"nb_shares", shares.size()}};
  if (!ghs.empty())
  {
    std::vector<nlohmann::json> unlockKeys;
    std::transform(begin(ghs),
                   end(ghs),
                   std::back_inserter(unlockKeys),
                   [&password](auto const& ghost) -> nlohmann::json {
                     auto ret =
                         nlohmann::json{{"user_id", ghost.userId},
                                        {"unlock_key", ghost.asUnlockKey()}};
                     if (!password.empty())
                       ret["password"] = password.as<std::string>();
                     return ret;
                   });
    tcInfos["users"] = unlockKeys;
  }
  else
  {
    std::vector<Tanker::SUserId> userIds;
    userIds.reserve(users.size());
    std::transform(begin(users),
                   end(users),
                   std::back_inserter(userIds),
                   [](auto const& user) { return user.userId; });
    tcInfos["users"] = userIds;
  }
  return tcInfos.dump(2);
}

TGen::Gen userOrCreate(po::variables_map const& vm)
{
  auto const url = value_or(vm["url"], defaultUrl);
  auto const token = value_or(vm["token"], tokenId);
  auto const keep = vm["keep"].as<bool>();
  auto const create = vm["new"].as<bool>();
  auto const tidkey = vm["trustchainKey"].as<std::string>();
  auto const nbConn = vm["connection"].as<std::size_t>();

  auto gen = TGen::Gen(url, token, nbConn);
  if (create == true)
    gen.create(keep);
  else if (!tidkey.empty())
  {
    auto split = tidkey.find_first_of('.');
    if (split == tidkey.npos)
      throw std::runtime_error(
          "Wrong format, expected <trustchainId>.<privateKey>");
    auto const tid = tidkey.substr(0, split);
    auto const key = tidkey.substr(split + 1);
    gen.use(tid, key);
  }
  else
    throw std::runtime_error(
        "Either specify if you want to use or create trustchain");
  return gen;
}
}

int main(int ac, char** argv)
{
  Tanker::init();
  // Declare the supported options.
  po::options_description desc("Allowed options");
  desc.add_options()("help", "produce help message")(
      "trustchainKey,t",
      po::value<std::string>()->default_value(""),
      "use the specified trustchainId, format is <tId>.<privateKey>")(
      "new,n",
      po::value<bool>()->default_value(false),
      "create a new trustchain")("connection,c",
                                 po::value<std::size_t>()->default_value(1),
                                 "how many connectins to use")(
      "keep,k",
      po::value<bool>()->default_value(false),
      "keep the created trustchain")(
      "url", po::value<std::string>()->default_value(defaultUrl), "the url")(
      "token", po::value<std::string>())(
      "users,u",
      po::value<std::size_t>()->default_value(1),
      "how many users to create")("ghost,g",
                                  po::value<bool>()->default_value(false),
                                  "create ghost device for all users")(
      "password,p",
      po::value<std::string>(),
      "set an unlock password for all users, implies ghost device")(
      "shares,s",
      po::value<std::size_t>()->default_value(1),
      "how many times a random user share to everyone")(
      "dump-json,d",
      po::value<std::string>()->default_value("-"),
      "dump users and trustchain specs to json");

  po::variables_map vm;
  po::store(po::parse_command_line(ac, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help"))
  {
    fmt::print(fmt::color::yellow, "{}: {}", argv[0], desc);
    return 1;
  }

  auto gen = userOrCreate(vm);

  fmt::print(fmt::color::yellow,
             "the trustchain name '{}' and Id '{}' \n",
             gen.name(),
             gen.trustchainId());

  using TGen::Nature;
  auto const users = gen.make(
      TGen::make_quantity<Nature::User>(vm["users"].as<std::size_t>()));

  if (users.empty())
  {
    fmt::print(fmt::color::red, "no users created, aborting");
    return 2;
  }

  TGen::Devices ghs;
  auto createUnlockKey = vm["ghost"].as<bool>() || !vm["password"].empty();
  auto const unlockPassword = TGen::UnlockPassword{
      value_or(vm["password"], "everyone gets a password!"s).c_str()};
  if (createUnlockKey)
    ghs = gen.make(unlockPassword, users);

  auto const shares = gen.make(
      TGen::make_quantity<Nature::Share>(vm["shares"].as<std::size_t>()),
      users);

  gen.dispatch(begin(users), end(users));
  gen.dispatch(begin(ghs), end(ghs));
  gen.upload(unlockPassword, ghs);
  gen.pushKeys(shares);

  fmt::print(fmt::color::green,
             "Success! '{}' contains {} users, {} ghostDevices, {} "
             "shares. That's {} blocks pushed!\n",
             gen.name(),
             users.size(),
             ghs.size(),
             shares.size(),
             shares.size() + users.size() + ghs.size());

  if (!dump(vm["dump-json"],
            trustchainInfos(gen, users, ghs, vm["password"], shares)))
    return 3;
  return 0;
}
