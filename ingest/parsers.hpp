#pragma once

#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace sentinelle {
namespace ingest {

using json = nlohmann::json;

/**
 * @brief Parse result with optional error
 */
template <typename T> struct ParseResult {
  std::optional<T> value;
  std::string error_message;

  bool is_success() const { return value.has_value(); }
  operator bool() const { return is_success(); }
};

/**
 * @brief JSON parser with security constraints
 */
class JsonParser {
public:
  /**
   * @brief Parse JSON string
   * @param input JSON string
   * @param max_depth Maximum nesting depth (default: 32)
   * @return Parse result
   */
  static ParseResult<json> parse(const std::string &input,
                                 size_t max_depth = 32);

  /**
   * @brief Safely get string value from JSON
   * @param j JSON object
   * @param key Key to retrieve
   * @return Optional string value
   */
  static std::optional<std::string> get_string(const json &j,
                                               const std::string &key);

  /**
   * @brief Safely get integer value from JSON
   * @param j JSON object
   * @param key Key to retrieve
   * @return Optional integer value
   */
  static std::optional<int64_t> get_int(const json &j, const std::string &key);
};

/**
 * @brief XML/HTML parser with security constraints
 */
class XmlParser {
public:
  /**
   * @brief Parse XML string
   * @param input XML string
   * @return Parse result with key-value pairs
   */
  static ParseResult<std::map<std::string, std::string>>
  parse_xml(const std::string &input);

  /**
   * @brief Parse HTML string and extract text
   * @param input HTML string
   * @return Parse result with extracted text
   */
  static ParseResult<std::string> parse_html(const std::string &input);

  /**
   * @brief Extract all links from HTML
   * @param input HTML string
   * @return Parse result with list of URLs
   */
  static ParseResult<std::vector<std::string>>
  extract_links(const std::string &input);
};

/**
 * @brief Plain text parser with encoding detection
 */
class TextParser {
public:
  /**
   * @brief Detect text encoding
   * @param input Raw bytes
   * @return Detected encoding name (e.g., "UTF-8", "ASCII")
   */
  static std::string detect_encoding(const std::vector<uint8_t> &input);

  /**
   * @brief Parse text with encoding conversion
   * @param input Raw bytes
   * @return Parse result with UTF-8 string
   */
  static ParseResult<std::string> parse(const std::vector<uint8_t> &input);

  /**
   * @brief Extract lines from text
   * @param input Text string
   * @param max_lines Maximum number of lines to extract
   * @return Vector of lines
   */
  static std::vector<std::string> extract_lines(const std::string &input,
                                                size_t max_lines = 10000);
};

} // namespace ingest
} // namespace sentinelle
