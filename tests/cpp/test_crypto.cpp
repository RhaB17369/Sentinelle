#include "../../core/crypto.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace sentinelle::crypto;

// Test SHA-256 hashing
TEST(CryptoTest, SHA256Basic) {
  std::string input = "Hello, World!";
  std::string hash = sha256_hex(input);

  // Known SHA-256 hash of "Hello, World!"
  std::string expected =
      "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";

  EXPECT_EQ(hash, expected);
}

TEST(CryptoTest, SHA256Empty) {
  std::string input = "";
  std::string hash = sha256_hex(input);

  // Known SHA-256 hash of empty string
  std::string expected =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  EXPECT_EQ(hash, expected);
}

// Test SHA-512 hashing
TEST(CryptoTest, SHA512Basic) {
  std::string input = "Hello, World!";
  std::string hash = sha512_hex(input);

  // Known SHA-512 hash of "Hello, World!"
  std::string expected =
      "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6c"
      "c69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387";

  EXPECT_EQ(hash, expected);
}

// Test HMAC-SHA256
TEST(CryptoTest, HMACSHA256) {
  std::vector<uint8_t> key = {'k', 'e', 'y'};
  std::vector<uint8_t> data = {'d', 'a', 't', 'a'};
  uint8_t output[32];

  bool result = hmac_sha256(key, data, output);

  EXPECT_TRUE(result);

  // Convert to hex for verification
  std::string hex = bytes_to_hex(output, 32);
  EXPECT_EQ(hex.length(), 64); // 32 bytes = 64 hex chars
}

// Test constant-time comparison
TEST(CryptoTest, ConstantTimeCompare) {
  std::vector<uint8_t> a = {1, 2, 3, 4, 5};
  std::vector<uint8_t> b = {1, 2, 3, 4, 5};
  std::vector<uint8_t> c = {1, 2, 3, 4, 6};

  EXPECT_TRUE(constant_time_compare(a, b));
  EXPECT_FALSE(constant_time_compare(a, c));
}

// Test hex conversion
TEST(CryptoTest, HexConversion) {
  std::vector<uint8_t> bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  std::string hex = bytes_to_hex(bytes.data(), bytes.size());

  EXPECT_EQ(hex, "0123456789abcdef");

  // Convert back
  std::vector<uint8_t> decoded = hex_to_bytes(hex);
  EXPECT_EQ(decoded, bytes);
}

// Test SecureBuffer
TEST(CryptoTest, SecureBuffer) {
  {
    SecureBuffer buf(32);
    EXPECT_EQ(buf.size(), 32);
    EXPECT_NE(buf.data(), nullptr);

    // Write some data
    for (size_t i = 0; i < buf.size(); ++i) {
      buf.data()[i] = static_cast<uint8_t>(i);
    }
  }
  // Buffer should be zeroized on destruction
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
