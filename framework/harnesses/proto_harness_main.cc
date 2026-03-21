
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, std::size_t size);

int main(int argc, char *argv[])
{
    int rc = 0;
    for (int idx = 1; idx < argc; idx++) {
        std::ifstream file(argv[idx]);
        std::istreambuf_iterator input = std::istreambuf_iterator<char>{file};
        std::istreambuf_iterator eof = std::istreambuf_iterator<char>();
        std::vector<uint8_t> buf(input, eof);
        std::cout << "[*] Replaying " << argv[idx] << std::endl;
        rc = LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    return rc;
}