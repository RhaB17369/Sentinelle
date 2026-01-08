#include "parsers.hpp"
#include <regex>
#include <sstream>

namespace sentinelle {
namespace ingest {

// JSON Parser implementation
ParseResult<json> JsonParser::parse(const std::string &input,
                                    size_t max_depth) {
  ParseResult<json> result;

  if (input.empty()) {
    result.error_message = "Empty JSON input";
    return result;
  }

  if (input.size() > 10 * 1024 * 1024) {
    result.error_message = "JSON input exceeds maximum size (10 MB)";
    return result;
  }

  try {
    json parsed = json::parse(input);

    // Check depth (simplified - nlohmann::json doesn't have built-in depth
    // check) In production, implement recursive depth checking

    result.value = parsed;
  } catch (const json::parse_error &e) {
    result.error_message = std::string("JSON parse error: ") + e.what();
  } catch (const std::exception &e) {
    result.error_message = std::string("JSON error: ") + e.what();
  }

  return result;
}

std::optional<std::string> JsonParser::get_string(const json &j,
                                                  const std::string &key) {
  try {
    if (j.contains(key) && j[key].is_string()) {
      return j[key].get<std::string>();
    }
  } catch (...) {
    // Ignore errors
  }
  return std::nullopt;
}

std::optional<int64_t> JsonParser::get_int(const json &j,
                                           const std::string &key) {
  try {
    if (j.contains(key) && j[key].is_number_integer()) {
      return j[key].get<int64_t>();
    }
  } catch (...) {
    // Ignore errors
  }
  return std::nullopt;
}

// XML Parser implementation (simplified without libxml2)
ParseResult<std::map<std::string, std::string>>
XmlParser::parse_xml(const std::string &input) {
  ParseResult<std::map<std::string, std::string>> result;

  if (input.empty()) {
    result.error_message = "Empty XML input";
    return result;
  }

  if (input.size() > 10 * 1024 * 1024) {
    result.error_message = "XML input exceeds maximum size";
    return result;
  }

  // Simplified XML parsing using regex
  // This is a basic implementation - for production use libxml2
  std::map<std::string, std::string> data;

  try {
    // Extract simple tags: <tag>value</tag>
    std::regex tag_regex("<([a-zA-Z0-9_-]+)>([^<]*)</\\1>");
    std::smatch matches;

    std::string::const_iterator search_start(input.cbegin());
    while (std::regex_search(search_start, input.cend(), matches, tag_regex)) {
      if (matches.size() >= 3) {
        std::string tag = matches[1];
        std::string value = matches[2];
        data[tag] = value;
      }
      search_start = matches.suffix().first;
    }
  } catch (const std::exception &e) {
    result.error_message = std::string("XML parse error: ") + e.what();
    return result;
  }

  result.value = data;
  return result;
}

ParseResult<std::string> XmlParser::parse_html(const std::string &input) {
  ParseResult<std::string> result;

  if (input.empty()) {
    result.error_message = "Empty HTML input";
    return result;
  }

  if (input.size() > 10 * 1024 * 1024) {
    result.error_message = "HTML input exceeds maximum size";
    return result;
  }

  // Simplified HTML parsing - extract text content
  try {
    std::string text = input;

    // Remove script and style tags
    std::regex script_regex("<script[^>]*>.*?</script>", std::regex::icase);
    text = std::regex_replace(text, script_regex, "");

    std::regex style_regex("<style[^>]*>.*?</style>", std::regex::icase);
    text = std::regex_replace(text, style_regex, "");

    // Remove all HTML tags
    std::regex tag_regex("<[^>]*>");
    text = std::regex_replace(text, tag_regex, " ");

    // Clean up whitespace
    std::regex whitespace_regex("\\s+");
    text = std::regex_replace(text, whitespace_regex, " ");

    // Trim
    text.erase(0, text.find_first_not_of(" \t\r\n"));
    text.erase(text.find_last_not_of(" \t\r\n") + 1);

    result.value = text;
  } catch (const std::exception &e) {
    result.error_message = std::string("HTML parse error: ") + e.what();
  }

  return result;
}

ParseResult<std::vector<std::string>>
XmlParser::extract_links(const std::string &input) {
  ParseResult<std::vector<std::string>> result;

  if (input.empty()) {
    result.error_message = "Empty HTML input";
    return result;
  }

  std::vector<std::string> links;

  try {
    // Extract href attributes using regex
    // Matches: href="..." or href='...'
    std::regex href_regex("href=[\"']([^\"']+)[\"']", std::regex::icase);
    std::smatch matches;

    std::string::const_iterator search_start(input.cbegin());
    while (std::regex_search(search_start, input.cend(), matches, href_regex)) {
      if (matches.size() >= 2) {
        links.push_back(matches[1]);
      }
      search_start = matches.suffix().first;
    }
  } catch (const std::exception &e) {
    result.error_message = std::string("Link extraction error: ") + e.what();
    return result;
  }

  result.value = links;
  return result;
}

// Text Parser implementation
std::string TextParser::detect_encoding(const std::vector<uint8_t> &input) {
  // Simplified encoding detection
  // Check for UTF-8 BOM
  if (input.size() >= 3 && input[0] == 0xEF && input[1] == 0xBB &&
      input[2] == 0xBF) {
    return "UTF-8";
  }

  // Check if valid UTF-8
  bool is_utf8 = true;
  for (size_t i = 0; i < input.size();) {
    uint8_t byte = input[i];

    if (byte < 0x80) {
      i++;
    } else if ((byte & 0xE0) == 0xC0) {
      if (i + 1 >= input.size() || (input[i + 1] & 0xC0) != 0x80) {
        is_utf8 = false;
        break;
      }
      i += 2;
    } else if ((byte & 0xF0) == 0xE0) {
      if (i + 2 >= input.size() || (input[i + 1] & 0xC0) != 0x80 ||
          (input[i + 2] & 0xC0) != 0x80) {
        is_utf8 = false;
        break;
      }
      i += 3;
    } else if ((byte & 0xF8) == 0xF0) {
      if (i + 3 >= input.size() || (input[i + 1] & 0xC0) != 0x80 ||
          (input[i + 2] & 0xC0) != 0x80 || (input[i + 3] & 0xC0) != 0x80) {
        is_utf8 = false;
        break;
      }
      i += 4;
    } else {
      is_utf8 = false;
      break;
    }
  }

  return is_utf8 ? "UTF-8" : "ASCII";
}

ParseResult<std::string> TextParser::parse(const std::vector<uint8_t> &input) {
  ParseResult<std::string> result;

  if (input.empty()) {
    result.value = "";
    return result;
  }

  if (input.size() > 10 * 1024 * 1024) {
    result.error_message = "Text input exceeds maximum size";
    return result;
  }

  // For simplicity, assume UTF-8 or ASCII
  result.value = std::string(input.begin(), input.end());

  return result;
}

std::vector<std::string> TextParser::extract_lines(const std::string &input,
                                                   size_t max_lines) {
  std::vector<std::string> lines;
  std::istringstream stream(input);
  std::string line;

  while (std::getline(stream, line) && lines.size() < max_lines) {
    lines.push_back(line);
  }

  return lines;
}

} // namespace ingest
} // namespace sentinelle
