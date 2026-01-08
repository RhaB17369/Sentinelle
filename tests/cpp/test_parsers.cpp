#include "../../ingest/parsers.hpp"
#include <gtest/gtest.h>

using namespace sentinelle::ingest;

// Test JSON parsing
TEST(ParsersTest, ValidJSON) {
  std::string json = R"({"key": "value", "number": 42})";

  auto result = JsonParser::parse(json);

  EXPECT_TRUE(result.is_success());
  EXPECT_TRUE(result.value.has_value());
}

TEST(ParsersTest, InvalidJSON) {
  std::string json = "{invalid json}";

  auto result = JsonParser::parse(json);

  EXPECT_FALSE(result.is_success());
  EXPECT_FALSE(result.error_message.empty());
}

TEST(ParsersTest, EmptyJSON) {
  std::string json = "";

  auto result = JsonParser::parse(json);

  EXPECT_FALSE(result.is_success());
}

// Test HTML parsing
TEST(ParsersTest, ValidHTML) {
  std::string html = "<html><body><p>Hello World</p></body></html>";

  auto result = XmlParser::parse_html(html);

  EXPECT_TRUE(result.is_success());
  EXPECT_TRUE(result.value.has_value());
}

TEST(ParsersTest, ExtractLinks) {
  std::string html =
      R"(<html><body><a href="http://example.com">Link</a></body></html>)";

  auto result = XmlParser::extract_links(html);

  EXPECT_TRUE(result.is_success());
  EXPECT_TRUE(result.value.has_value());
  EXPECT_EQ(result.value->size(), 1);
  EXPECT_EQ((*result.value)[0], "http://example.com");
}

// Test malformed input handling
TEST(ParsersTest, MalformedHTML) {
  std::string html = "<html><body><p>Unclosed tag";

  auto result = XmlParser::parse_html(html);

  // Should still parse (HTML parser is lenient)
  EXPECT_TRUE(result.is_success());
}

// Test text parsing
TEST(ParsersTest, TextParsing) {
  std::vector<uint8_t> input = {'H', 'e', 'l', 'l', 'o'};

  auto result = TextParser::parse(input);

  EXPECT_TRUE(result.is_success());
  EXPECT_EQ(*result.value, "Hello");
}

TEST(ParsersTest, ExtractLines) {
  std::string text = "Line 1\nLine 2\nLine 3";

  auto lines = TextParser::extract_lines(text);

  EXPECT_EQ(lines.size(), 3);
  EXPECT_EQ(lines[0], "Line 1");
  EXPECT_EQ(lines[1], "Line 2");
  EXPECT_EQ(lines[2], "Line 3");
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
