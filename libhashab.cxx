#include <curl/curl.h>

#include <string>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport)
#endif

extern "C" {

static std::string
url_encode(const std::string &value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; i++) {
    std::string::value_type c = (*i);
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else if (c == ' ')  {
      escaped << '+';
    } else {
      escaped << '%' << std::setw(2) << ((int) c) << std::setw(0);
    }
  }
  return escaped.str();
}

static std::string
to_hex(const unsigned char* data, size_t len) {
  static const char* const lut = "0123456789abcdef";
  std::string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; i++) {
    const unsigned char c = data[i];
    output.push_back(lut[c >> 4]);
    output.push_back(lut[c & 15]);
  }
  return output;
}

static std::string
from_hex(const std::string& input, size_t len) {
  static const char* const lut = "0123456789abcdef";
  if (len & 1) throw std::invalid_argument("odd length");
  std::string output;
  output.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    char* p1 = strchr(lut, tolower(input[i]));
    if (!p1) throw std::invalid_argument("not a hex digit");
    char* p2 = strchr(lut, tolower(input[i + 1]));
    if (!p2) throw std::invalid_argument("not a hex digit");
    output.push_back((unsigned char) ((p1 - lut) << 4) | (p2 - lut));
  }
  return output;
}

typedef struct {
  char* data;     // response data from server
  size_t size;    // response size of data
} MEMFILE;

static MEMFILE*
memfopen() {
  MEMFILE* mf = (MEMFILE*) malloc(sizeof(MEMFILE));
  if (mf) {
    mf->data = NULL;
    mf->size = 0;
  }
  return mf;
}

static void
memfclose(MEMFILE* mf) {
  if (mf->data) free(mf->data);
  free(mf);
}

static size_t
memfwrite(char* ptr, size_t size, size_t nmemb, void* stream) {
  MEMFILE* mf = (MEMFILE*) stream;
  int block = size * nmemb;
  if (!mf) return block; // through
  if (!mf->data)
    mf->data = (char*) malloc(block);
  else
    mf->data = (char*) realloc(mf->data, mf->size + block);
  if (mf->data) {
    memcpy(mf->data + mf->size, ptr, block);
    mf->size += block;
  }
  return block;
}

EXPORT int
calcHashAB(unsigned char target[57], unsigned char sha1[20], unsigned char uuid[20], unsigned char rndb[23]) {
  CURL* curl;
  CURLcode res = CURLE_OK;
  MEMFILE* mf;
  long status = 0;
  char* ptr;
  char* top;
  size_t len;
  char* endpoint = getenv("LIBHASHAB_ENDPOINT");

  memset(target, 0, 57);
  if (endpoint == NULL) {
    std::cerr << "[libhashab] $LIBHASHAB_ENDPOINT doesn't set" << std::endl;
    return 1;
  }
  std::string url = endpoint;
  url += "?sha1=";
  url += to_hex(sha1, 20);
  url += "&uuid=";
  url += to_hex(uuid, 20);
  url += "&rndb=";
  url += to_hex(rndb, 23);
  std::cerr << "[libhashab] Request: " << url.c_str() << std::endl;

  mf = memfopen();
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, mf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, memfwrite);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
  if (res != CURLE_OK || status != 200) {
    std::cerr << "[libhashab] Bad response: " << status << std::endl;
    memfclose(mf);
    return 1;
  }
  top = mf->data;
  while (*ptr && !isalnum(*ptr)) {
    top++;
  }
  ptr = top;
  len = 0;
  while (*ptr && isalnum(*ptr)) {
    len++;
    ptr++;
  }
  try {
    std::cerr << "[libhashab] Response: " << std::string(top, len) << std::endl;
    std::string bin = from_hex(top, len);
    memfclose(mf);
    memcpy(target, bin.data(), std::min((int) bin.size(), 57));
  } catch (std::invalid_argument& e) {
    std::cerr << "[libhashab] Exception: " << e.what() << std::endl;
    memfclose(mf);
    return 1;
  }
  return 0;
}

}
