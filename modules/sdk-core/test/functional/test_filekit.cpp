#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Retry.hpp>
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
  TC_AWAIT(retry(cb, DelayList(4)));
  CHECK(*cb.called == 3);
}

TEST_CASE("it auto retries until it gives up")
{
  auto cb = SucceedAt(15);
  CHECK_THROWS_AS(TC_AWAIT(retry(cb, DelayList(4))), Errors::Exception);
  CHECK(*cb.called == 5);
}

namespace
{
FileKit::Metadata makeMetadata()
{
  FileKit::Metadata metadata;
  metadata.mime = "image/jpeg";
  metadata.name = "holidays.jpg";
  metadata.lastModified = std::chrono::milliseconds(128128);
  return metadata;
}

tc::cotask<void> testUploadDownload(Test::Trustchain& trustchain, uint64_t size)
{
  CAPTURE(size);
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  auto const metadata = makeMetadata();
  std::vector<uint8_t> buffer(size);
  Crypto::randomFill(buffer);
  auto const resourceId = TC_AWAIT(core->upload(buffer, metadata));
  auto const downloadResult = TC_AWAIT(core->download(resourceId));
  CHECK(downloadResult.data == buffer);
  CHECK(downloadResult.metadata.mime == metadata.mime);
  CHECK(downloadResult.metadata.name == metadata.name);
  CHECK(downloadResult.metadata.lastModified == metadata.lastModified);
}
}

TEST_SUITE_BEGIN("FileKit");

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit upload/download small file")
{
  TC_AWAIT(testUploadDownload(trustchain, 30));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit upload/download big file")
{
  TC_AWAIT(testUploadDownload(trustchain, 5 * 1024 * 1024));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit upload/download with two users")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceCore = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobCore = TC_AWAIT(bobDevice.open());

  auto const metadata = makeMetadata();
  auto const buffer = make_buffer("this is a test");
  auto const resourceId =
      TC_AWAIT(aliceCore->upload(buffer, metadata, {bob.spublicIdentity()}));
  auto const downloadResult = TC_AWAIT(bobCore->download(resourceId));

  CHECK(downloadResult.data == buffer);
  CHECK(downloadResult.metadata.mime == metadata.mime);
  CHECK(downloadResult.metadata.name == metadata.name);
  CHECK(downloadResult.metadata.lastModified == metadata.lastModified);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Filekit download 404")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(core->download(cppcodec::base64_rfc4648::encode<SResourceId>(
          make<Trustchain::ResourceId>("no such resource")))),
      Errors::Errc::InvalidArgument);
}

TEST_SUITE_END();
