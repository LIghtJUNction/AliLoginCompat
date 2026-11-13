#include "../app/src/main/cpp/policy.hpp"
#include <cassert>

int main() {
    ali::Record sample{0x11,0xa0,0x85,0x04,0x80,0x09,0x10,0,0x22,0x33};
    assert(ali::matches(sample.data(), 18));
    assert(!ali::matches(nullptr, 18));
    assert(!ali::matches(sample.data(), 17));
    assert(!ali::matches(sample.data(), 19));
    auto result = ali::rewrite(sample.data());
    for (int i = 0; i < 18; ++i) assert(result[i] == ((i >= 1 && i < 8) ? 0 : sample[i]));
    assert(sample[1] == 0xa0); // source is not mutated
    for (int i : {0,8,9,10,17}) {
        auto bad = sample; bad[i] ^= 1;
        assert(!ali::matches(bad.data(), 18));
    }
    assert(ali::matches(result.data(), 18));
    ali::Record taobao{0,0,0x80,0,0x80,0,0x10,0,0x22,0x33,0,0,0,0,0,4,0,0};
    assert(ali::matches(taobao.data(), 18, ali::Format::Taobao));
    assert(!ali::matches(taobao.data(), 18, ali::Format::Idlefish));
    assert(!ali::matches(sample.data(), 18, ali::Format::Taobao));
    auto tb_result = ali::rewrite(taobao.data());
    for (int i = 0; i < 18; ++i) assert(tb_result[i] == ((i >= 1 && i < 8) ? 0 : taobao[i]));
    assert(taobao[2] == 0x80 && taobao[15] == 4);
    assert(ali::matches(tb_result.data(), 18, ali::Format::Taobao));
    for (int i : {0,8,9,10,15,17}) {
        auto bad = taobao; bad[i] ^= 1;
        assert(!ali::matches(bad.data(), 18, ali::Format::Taobao));
    }
    auto taobao_second = taobao; taobao_second[0] = 0x10;
    assert(ali::matches(taobao_second.data(), 18, ali::Format::Taobao));
    assert(ali::rewrite(taobao_second.data())[0] == 0x10);
    return 0;
}
