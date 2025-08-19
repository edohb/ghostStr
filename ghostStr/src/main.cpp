#include <cstdio>
#include "ghoststr.hpp"

int main() {
    auto string = ghostStr("This is an encrypted string!");
    {
        auto view = string.scoped();
        printf("Decrypted String: %s\n", view.data());
    }

    return 0;
}