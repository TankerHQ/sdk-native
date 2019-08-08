#include <Tanker/CloudStorage.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace CloudStorage
{
void from_json(nlohmann::json const& json, UploadTicket& uploadTicket)
{
  json.at("url").get_to(uploadTicket.url);
  json.at("headers").get_to(uploadTicket.headers);
  json.at("service").get_to(uploadTicket.service);
}

void from_json(nlohmann::json const& json, DownloadTicket& downloadTicket)
{
  json.at("url").get_to(downloadTicket.url);
  json.at("service").get_to(downloadTicket.service);
}

tc::cotask<UploadTicket> getFileUploadTicket(
    Client& client, Trustchain::ResourceId const& resourceId, uint64_t length)
{
  nlohmann::json req{
      {"resource_id", resourceId},
      {"upload_content_length", length},
  };
  auto const res = TC_AWAIT(client.emit("get file upload url", req));
  TC_RETURN(res.get<UploadTicket>());
}

tc::cotask<DownloadTicket> getFileDownloadTicket(
    Client& client, Trustchain::ResourceId const& resourceId)
{
  nlohmann::json req{
      {"resource_id", resourceId},
  };
  auto const res = TC_AWAIT(client.emit("get file download url", req));
  TC_RETURN(res.get<DownloadTicket>());
}
}
}
