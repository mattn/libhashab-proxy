#include <curl/curl.h>

#include <string>
#include <iomanip>
#include <sstream>
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
  static const char* const lut = "0123456789ABCDEF";
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
  static const char* const lut = "0123456789ABCDEF";
  if (len & 1) throw std::invalid_argument("odd length");

  std::string output;
  output.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    char a = input[i];
    const char* p = std::lower_bound(lut, lut + 16, a);
    if (*p != a) throw std::invalid_argument("not a hex digit");
    char b = input[i + 1];
    const char* q = std::lower_bound(lut, lut + 16, b);
    if (*q != b) throw std::invalid_argument("not a hex digit");

    output.push_back(((p - lut) << 4) | (q - lut));
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

static char*
memfstrdup(MEMFILE* mf) {
  char* buf;
  if (mf->size == 0) return NULL;
  buf = (char*) malloc(mf->size + 1);
  memcpy(buf, mf->data, mf->size);
  buf[mf->size] = 0;
  return buf;
}

EXPORT int
calcHashAB(unsigned char target[57], unsigned char sha1[20], unsigned char uuid[20], unsigned char rndb[23]) {
  CURL* curl;
  CURLcode res = CURLE_OK;
  MEMFILE* mf;
  char* ptr;
  char* endpoint = getenv("LIBHASHAB_ENDPOINT");
  if (endpoint == NULL) {
    return 1;
  }
  std::string url = endpoint;
  url += "?sha1=";
  url += to_hex(sha1, sizeof(sha1));
  url += "&uuid=";
  url += to_hex(uuid, sizeof(uuid));
  url += "&rndb=";
  url += to_hex(rndb, sizeof(rndb));

  mf = memfopen();
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, mf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, memfwrite);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  if (res != CURLE_OK) {
    memfclose(mf);
    return 1;
  }
  std::string bin = from_hex(mf->data, mf->size);
  memfclose(mf);
  memcpy(target, bin.data(), sizeof(target));
  return 0;
}

EXPORT void
get_random_bytes_from_hashAB(unsigned char *hash, unsigned char *rndb) {
  rndb[0]  = hash[23];
  rndb[1]  = hash[13];
  rndb[2]  = hash[29];
  rndb[3]  = hash[12];
  rndb[4]  = hash[37];
  rndb[5]  = hash[8];
  rndb[6]  = hash[4];
  rndb[7]  = hash[6];
  rndb[8]  = hash[10];
  rndb[9]  = hash[41];
  rndb[10] = hash[53];
  rndb[11] = hash[27];
  rndb[12] = hash[5];
  rndb[13] = hash[43];
  rndb[14] = hash[28];
  rndb[15] = hash[45];
  rndb[16] = hash[16];
  rndb[17] = hash[46];
  rndb[18] = hash[34];
  rndb[19] = hash[9];
  rndb[20] = hash[19];
  rndb[21] = hash[2];
  rndb[22] = hash[56];
}

}
