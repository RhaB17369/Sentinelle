#include "../../ingest/http_client.hpp"
#include <gtest/gtest.h>

using namespace sentinelle::ingest;

// Test HTTP client configuration
TEST(HttpClientTest, Configuration) {
  HttpConfig config;
  config.timeout_seconds = 10;
  config.verify_ssl = true;

  HttpClient client(config);

  // Just verify construction succeeds
  SUCCEED();
}

// Test invalid URL rejection
TEST(HttpClientTest, InvalidURL) {
  HttpClient client;

  HttpResponse response = client.get("not a valid url");

  EXPECT_FALSE(response.is_success());
  EXPECT_FALSE(response.error_message.empty());
}

// Note: Actual HTTP tests would require a test server
// In production, use a mock HTTP server or integration tests

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
