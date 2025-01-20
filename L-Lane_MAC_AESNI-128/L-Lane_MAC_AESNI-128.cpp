#include <iostream>
#include <iomanip> // setfill(),setw()を使用
#include <wmmintrin.h> //AES_NIヘッダファイル
#include <vector> // メモリの動的確保に使用
#include <chrono> // 時間の計測に使用
#include <thread>

void L_Lane_MAC(std::vector<unsigned char> input, unsigned char* mac, const unsigned char* key);
void AES_128_Key_Expansion(const unsigned char* userkey, unsigned char* encrypt_keys);
void makeMAC_xLane(const unsigned char* input, unsigned char* out, int Lane_num, size_t length, const char* encrypt_keys);
void makeMAC_CBC(const unsigned char* input, unsigned char* out, size_t length, const char* encrypt_keys);
void AES_encrypt(__m128i* input, const char* encrypt_keys);

// ゼロ埋めされたstd::vectorを返す関数
std::vector<unsigned char> zeroOutMessage(size_t length) {
    std::vector<unsigned char> buffer(length); // 指定サイズのstd::vectorを確保
    std::memset(buffer.data(), 0x00, length); // メモリ全体を0x00で埋める
    return buffer;
}

int main()
{
    std::vector<unsigned char> input = zeroOutMessage(1024); // zeroOutMessage(バイト数)で指定
    const unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; // キー（16バイト）を指定
    unsigned char mac[16];

    int rep_cnt = 1; // 計測の回数を指定
    int func_cnt = 1; // 関数の繰り返し回数を指定

    //rep_cntの回数計測する
    for (int i = 0; i < rep_cnt; i++) {

         //↓ここから時間を計測する
        auto start = std::chrono::high_resolution_clock::now(); // 開始時間を記録

        for (int i = 0; i < func_cnt; i++) {
             L_Lane_MAC(input, mac, key);
        }
        auto end = std::chrono::high_resolution_clock::now(); // 終了時間を記録
         //↑計測ここまで

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start); // 経過時間を計算 (ミリ秒)
        std::cout << duration.count() << std::endl;
    }

    return 0;
}

void L_Lane_MAC(std::vector<unsigned char> input, unsigned char* mac, const unsigned char* key) {
    static unsigned char encrypt_keys[11 * 16]; // AES_NI-128の暗号用ラウンドキーを格納
    AES_128_Key_Expansion(key, encrypt_keys); // 鍵拡張
    
    //それぞれのレーンでMAC生成（並列処理）
    unsigned char L1_MAC[16], L2_MAC[16], L3_MAC[16];
    std::thread thread1(makeMAC_xLane, input.data(), L1_MAC, 1, input.size(), (const char*)encrypt_keys);
    std::thread thread2(makeMAC_xLane, input.data(), L2_MAC, 2, input.size(), (const char*)encrypt_keys);
    std::thread thread3(makeMAC_xLane, input.data(), L3_MAC, 3, input.size(), (const char*)encrypt_keys);
    thread1.join();
    thread2.join();
    thread3.join();
    
    //3つのMACを結合(必ず16*3バイトなのでパディングは不要)
    std::vector<unsigned char> last_data;
    last_data.insert(last_data.end(), L1_MAC, L1_MAC + 16);
    last_data.insert(last_data.end(), L2_MAC, L2_MAC + 16);
    last_data.insert(last_data.end(), L3_MAC, L3_MAC + 16);

    //その値でMAC生成
    makeMAC_CBC(last_data.data(), mac, last_data.size(), (const char*)encrypt_keys);
}

// 鍵拡張のサポート関数
inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

// 鍵拡張の関数
void AES_128_Key_Expansion(const unsigned char* userkey, unsigned char* encrypt_keys) {
    __m128i temp1, temp2;
    __m128i* Key_Schedule = (__m128i*)encrypt_keys;

    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

void makeMAC_xLane(const unsigned char* input, unsigned char* out, int Lane_num, size_t length, const char* encrypt_keys) {
    __m128i feedfront, data;
    unsigned int i;
    static unsigned char ivec[16] = { 0 }; // CBC-MACでは初期ベクトルは０
    static unsigned char buf[16]{};
    feedfront = _mm_loadu_si128((__m128i*)ivec);
    size_t blocks = length / 32;
    size_t last_data_length = length % 32;

    switch (Lane_num) {
    case 1:
        for (i = 0; i < blocks; i++) {
            data = _mm_loadu_si128(&((__m128i*)input)[i * 2]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
        }
        if (last_data_length == 0) {
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else if (last_data_length % 16 == 0) {
            data = _mm_loadu_si128(&((__m128i*)input)[i * 2]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else {
            std::memcpy(buf, &((__m128i*)input)[i * 2], last_data_length);
            data = _mm_loadu_si128(&((__m128i*)buf)[0]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
    case 2:
        for (i = 0; i < blocks; i++) {
            data = _mm_loadu_si128(&((__m128i*)input)[i * 2 + 1]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
        }
        if (last_data_length == 0) {
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else if (last_data_length % 16 == 0) {
            data = _mm_loadu_si128(&((__m128i*)buf)[0]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else {
            std::memcpy(buf, &((__m128i*)input)[i * 2 + 1], last_data_length - 16);
            data = _mm_loadu_si128(&((__m128i*)buf)[0]);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
    case 3:
        __m128i odd, even;
        for (i = 0; i < blocks; i++) {
            odd = _mm_loadu_si128(&((__m128i*)input)[i * 2]);
            even = _mm_loadu_si128(&((__m128i*)input)[i * 2 + 1]);
            data = _mm_xor_si128(odd, even);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
        }
        if (last_data_length == 0) {
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else if (last_data_length % 16 == 0) {
            odd = _mm_loadu_si128(&((__m128i*)input)[i * 2]);
            even = _mm_loadu_si128(&((__m128i*)buf)[0]);
            data = _mm_xor_si128(odd, even);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
        else {
            std::memcpy(buf, &((__m128i*)input)[i * 2 + 1], last_data_length - 16);
            odd = _mm_loadu_si128(&((__m128i*)input)[i * 2]);
            even = _mm_loadu_si128(&((__m128i*)buf)[0]);
            data = _mm_xor_si128(odd, even);
            feedfront = _mm_xor_si128(data, feedfront);
            AES_encrypt(&feedfront, (const char*)encrypt_keys);
            ((__m128i*)out)[0] = feedfront;
            break;
        }
    default:
        std::cout << "Invalid number" << std::endl;
        break;
    }
}

// CBCモードでMACを生成する関数
void makeMAC_CBC(const unsigned char* input, unsigned char* out, size_t length, const char* encrypt_keys) {
    __m128i feedfront, data;
    static unsigned char ivec[16] = { 0 }; // CBC-MACでは初期ベクトルは０
    size_t blocks = length / 16;

    feedfront = _mm_loadu_si128((__m128i*)ivec);
    for (unsigned int i = 0; i < blocks; i++) {
        data = _mm_loadu_si128(&((__m128i*)input)[i]);
        feedfront = _mm_xor_si128(data, feedfront);
        AES_encrypt(&feedfront, (const char*)encrypt_keys);
    }
    ((__m128i*)out)[0] = feedfront; // 最終ブロックの暗号文(MAC)だけ出力
}

// 1ブロック暗号関数
void AES_encrypt(__m128i* input, const char* encrypt_keys) {
    __m128i tmp;
    int i;

    // AES-128なので10ラウンド
    tmp = _mm_loadu_si128(input);
    tmp = _mm_xor_si128(tmp, ((__m128i*)encrypt_keys)[0]);

    for (i = 1; i < 10; i++) {
        tmp = _mm_aesenc_si128(tmp, ((__m128i*)encrypt_keys)[i]);
    }

    tmp = _mm_aesenclast_si128(tmp, ((__m128i*)encrypt_keys)[i]);
    _mm_storeu_si128(input, tmp);
}