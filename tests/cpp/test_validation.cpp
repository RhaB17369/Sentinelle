#include "../../core/validation.hpp"
#include <gtest/gtest.h>

using namespace sentinelle::validation;

// Test URL validation
TEST(ValidationTest, ValidURL) {
  EXPECT_TRUE(validate_url("https://example.com"));
  EXPECT_TRUE(validate_url("http://example.com:8080/path"));
  EXPECT_TRUE(validate_url("https://sub.example.com/path?query=value"));
}

TEST(ValidationTest, InvalidURL) {
  EXPECT_FALSE(validate_url(""));
  EXPECT_FALSE(validate_url("not a url"));
  EXPECT_FALSE(validate_url("ftp://example")); // Missing domain extension
}

// Test IPv4 validation
TEST(ValidationTest, ValidIPv4) {
  EXPECT_TRUE(validate_ipv4("192.168.1.1"));
  EXPECT_TRUE(validate_ipv4("8.8.8.8"));
  EXPECT_TRUE(validate_ipv4("127.0.0.1"));
}

TEST(ValidationTest, InvalidIPv4) {
  EXPECT_FALSE(validate_ipv4("256.1.1.1"));
  EXPECT_FALSE(validate_ipv4("192.168.1"));
  EXPECT_FALSE(validate_ipv4("not an ip"));
}

// Test IPv6 validation
TEST(ValidationTest, ValidIPv6) {
  EXPECT_TRUE(validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  EXPECT_TRUE(validate_ipv6("::1"));
  EXPECT_TRUE(validate_ipv6("fe80::1"));
}

TEST(ValidationTest, InvalidIPv6) {
  EXPECT_FALSE(validate_ipv6("not an ipv6"));
  EXPECT_FALSE(validate_ipv6("192.168.1.1"));
}

// Test domain validation
TEST(ValidationTest, ValidDomain) {
  EXPECT_TRUE(validate_domain("example.com"));
  EXPECT_TRUE(validate_domain("sub.example.com"));
  EXPECT_TRUE(validate_domain("example-site.co.uk"));
}

TEST(ValidationTest, InvalidDomain) {
  EXPECT_FALSE(validate_domain(""));
  EXPECT_FALSE(validate_domain("-example.com"));
  EXPECT_FALSE(validate_domain("example-.com"));
  EXPECT_FALSE(validate_domain("exam ple.com"));
}

// Test email validation
TEST(ValidationTest, ValidEmail) {
  EXPECT_TRUE(validate_email("user@example.com"));
  EXPECT_TRUE(validate_email("user.name@example.co.uk"));
  EXPECT_TRUE(validate_email("user+tag@example.com"));
}

TEST(ValidationTest, InvalidEmail) {
  EXPECT_FALSE(validate_email(""));
  EXPECT_FALSE(validate_email("not an email"));
  EXPECT_FALSE(validate_email("@example.com"));
  EXPECT_FALSE(validate_email("user@"));
}

// Test phone validation
TEST(ValidationTest, ValidPhone) {
  EXPECT_TRUE(validate_phone("+1234567890"));
  EXPECT_TRUE(validate_phone("(123) 456-7890"));
  EXPECT_TRUE(validate_phone("123-456-7890"));
}

TEST(ValidationTest, InvalidPhone) {
  EXPECT_FALSE(validate_phone(""));
  EXPECT_FALSE(validate_phone("abc"));
  EXPECT_FALSE(validate_phone("123")); // Too short
}

// Test string sanitization
TEST(ValidationTest, SanitizeString) {
  std::string input = "Hello\x00World\x01Test";
  std::string sanitized = sanitize_string(input);

  // Should remove null and control characters
  EXPECT_EQ(sanitized.find('\x00'), std::string::npos);
  EXPECT_EQ(sanitized.find('\x01'), std::string::npos);
}

// Test safe string check
TEST(ValidationTest, SafeString) {
  EXPECT_TRUE(is_safe_string("abc123", ""));
  EXPECT_TRUE(is_safe_string("test-file_name", "-_"));
  EXPECT_FALSE(is_safe_string("test file", "")); // Space not allowed
  EXPECT_TRUE(is_safe_string("test file", " ")); // Space allowed
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
