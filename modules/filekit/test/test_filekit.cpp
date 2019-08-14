#include <Tanker/FileKit/FileKit.hpp>
#include <Tanker/FileKit/Retry.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace Tanker;

namespace
{
struct SucceedAt
{
  SucceedAt(int attempt) : attempt(attempt), called(std::make_shared<int>(0))
  {
  }

  int attempt;
  // this callback will be copied in the test, so we need a shared pointer
  std::shared_ptr<int> called;

  tc::cotask<void> operator()()
  {
    ++*called;
    if (*called <= attempt)
      throw Errors::formatEx(Errors::Errc::NetworkError, "test error");
    TC_RETURN();
  }
};
}

TEST_CASE("it auto retries until it works")
{
  auto cb = SucceedAt(2);
  TC_AWAIT(FileKit::retry(cb, FileKit::DelayList(4)));
  CHECK(*cb.called == 3);
}

TEST_CASE("it auto retries until it gives up")
{
  auto cb = SucceedAt(15);
  CHECK_THROWS_AS(TC_AWAIT(FileKit::retry(cb, FileKit::DelayList(4))),
                  Errors::Exception);
  CHECK(*cb.called == 5);
}

namespace
{
void testUploadDownload(Test::Trustchain& trustchain, uint64_t size)
{
  CAPTURE(size);
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  FileKit::FileKit storage(*core);
  FileKit::Metadata metadata;
  metadata.mime = "image/jpeg";
  metadata.name = "holidays.jpg";
  metadata.lastModified = std::chrono::milliseconds(128128);
  std::vector<uint8_t> buffer(size);
  Crypto::randomFill(buffer);
  auto const resourceId = TC_AWAIT(storage.upload(buffer, metadata));
  auto const downloadResult = TC_AWAIT(storage.download(resourceId));
  CHECK(std::get<0>(downloadResult) == buffer);
  CHECK(std::get<1>(downloadResult).mime == metadata.mime);
  CHECK(std::get<1>(downloadResult).name == metadata.name);
  CHECK(std::get<1>(downloadResult).lastModified == metadata.lastModified);
}
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit upload/download small file")
{
  testUploadDownload(trustchain, 30);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit upload/download big file")
{
  testUploadDownload(trustchain, 5 * 1024 * 1024);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit download 404")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  FileKit::FileKit storage(*core);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(
          storage.download(make<Trustchain::ResourceId>("no such resource"))),
      Errors::Errc::InvalidArgument);
}
