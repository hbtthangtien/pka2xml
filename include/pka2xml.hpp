#pragma once

#include <cryptopp/base64.h>
#include <cryptopp/cast.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>
#include <re2/re2.h>
#include <zlib.h>

#include <array>
#include <atomic>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <stdexcept>  // std::runtime_error

namespace pka2xml {

// ============================================================================
// CONFIG
// ============================================================================

// Chỉ dùng parallel cho data thực sự lớn
constexpr size_t MIN_SIZE_FOR_PARALLEL = 10000; // có thể tinh chỉnh sau khi profile
// Kích thước mỗi chunk khi chia việc cho threads
constexpr size_t CHUNK_SIZE           = 4096;

// ============================================================================
// INTERNAL: helper cho parallel
// ============================================================================

namespace detail {

inline unsigned hardware_threads() noexcept {
    unsigned hc = std::thread::hardware_concurrency();
    return hc ? hc : 2u;
}

/// parallel_for(length, func)
/// func(start, end) sẽ được gọi trên nhiều thread với [start, end)
template<typename Func>
inline void parallel_for(size_t length, Func&& func) {
    if (length == 0 || length < MIN_SIZE_FOR_PARALLEL) {
        // Dữ liệu nhỏ → chạy 1 thread cho nhanh
        func(0, length);
        return;
    }

    const unsigned hw = hardware_threads();
    const size_t   max_threads_by_size =
        (length + CHUNK_SIZE - 1) / CHUNK_SIZE;

    unsigned num_threads = static_cast<unsigned>(
        std::min<size_t>(hw, std::max<size_t>(1, max_threads_by_size)));

    if (num_threads <= 1) {
        func(0, length);
        return;
    }

    const size_t block_size = (length + num_threads - 1) / num_threads;
    std::vector<std::thread> threads;
    threads.reserve(num_threads - 1);

    size_t block_start = 0;
    for (unsigned t = 0; t + 1 < num_threads; ++t) {
        size_t block_end = std::min(block_start + block_size, length);
        threads.emplace_back(
            [&func, block_start, block_end]() {
                func(block_start, block_end);
            });
        block_start = block_end;
    }

    // Phần còn lại chạy trên thread hiện tại
    if (block_start < length) {
        func(block_start, length);
    }

    for (auto& th : threads) {
        th.join();
    }
}

} // namespace detail

// ============================================================================
// ZLIB
// ============================================================================

/// \brief Uncompress buffer with zlib. Opposite of `compress`.
/// data: buffer bắt đầu bằng 4 byte lưu original size (big-endian)
inline std::string uncompress(const unsigned char* data, int nbytes) {
    if (nbytes < 4) {
        throw std::runtime_error("uncompress: buffer too small");
    }

    unsigned long orig_len =
        (static_cast<unsigned long>(data[0]) << 24) |
        (static_cast<unsigned long>(data[1]) << 16) |
        (static_cast<unsigned long>(data[2]) << 8)  |
        (static_cast<unsigned long>(data[3]));

    if (orig_len == 0) {
        return {};
    }

    // Cấp phát trước đúng kích thước gốc (zlib có thể trả len <= orig_len)
    std::string result(static_cast<size_t>(orig_len), '\0');
    unsigned long len = orig_len;

    int res = ::uncompress(
        reinterpret_cast<Bytef*>(&result[0]),
        &len,
        data + 4,
        static_cast<uLong>(nbytes - 4)
    );
    if (res != Z_OK) {
        throw res;
    }

    // zlib cập nhật len thực tế
    result.resize(static_cast<size_t>(len));
    return result;
}

/// \brief Compress buffer with zlib. Opposite of `uncompress`.
/// Kết quả: 4 byte header (size gốc, big-endian) + data nén DEFLATE
inline std::string compress(const unsigned char* data, int nbytes) {
    if (nbytes <= 0) {
        // vẫn trả về 4 byte header size = 0
        return std::string(4, '\0');
    }

    // Estimate theo khuyến nghị zlib
    unsigned long len_est =
        static_cast<unsigned long>(nbytes + nbytes / 100 + 13);

    // +4 cho header size
    std::string result(static_cast<size_t>(len_est + 4), '\0');

    unsigned long len = len_est;

    int res = ::compress2(
        reinterpret_cast<Bytef*>(&result[4]),
        &len,
        data,
        static_cast<uLong>(nbytes),
        -1 // hoặc Z_BEST_SPEED nếu ưu tiên tốc độ hơn tỷ lệ nén
    );

    if (res != Z_OK) {
        throw res;
    }

    // resize đúng kích thước sau nén + 4 byte header
    result.resize(static_cast<size_t>(len + 4));

    // ghi size gốc big-endian
    result[0] = static_cast<unsigned char>((nbytes & 0xff000000) >> 24);
    result[1] = static_cast<unsigned char>((nbytes & 0x00ff0000) >> 16);
    result[2] = static_cast<unsigned char>((nbytes & 0x0000ff00) >> 8);
    result[3] = static_cast<unsigned char>((nbytes & 0x000000ff));

    return result;
}

// ============================================================================
// OBFUSCATION STAGES
// ============================================================================

/// \brief Deobfuscation stage 1 - parallel hóa theo chunk
/// output[i] = input[length-1-i] ^ (length - i * length)
inline void deobfuscate_stage1_parallel(const std::string& input,
                                        std::string& output) {
    const int length = static_cast<int>(input.size());
    if (length <= 0) {
        output.clear();
        return;
    }

    output.resize(static_cast<size_t>(length));

    auto worker = [&](size_t start, size_t end) {
        int s = static_cast<int>(start);
        int e = static_cast<int>(end);
        for (int i = s; i < e; ++i) {
            int j = length - 1 - i;
            output[static_cast<size_t>(i)] =
                static_cast<char>(input[static_cast<size_t>(j)] ^
                                  (length - i * length));
        }
    };

    detail::parallel_for(static_cast<size_t>(length), worker);
}

/// \brief Deobfuscation stage 3 - parallel version
/// output[i] ^= (size - i)
inline void deobfuscate_stage3_parallel(std::string& output) {
    const size_t size = output.size();

    auto worker = [&](size_t start, size_t end) {
        char* p = &output[0] + start;
        for (size_t i = start; i < end; ++i, ++p) {
            *p = static_cast<char>(*p ^ (size - i));
        }
    };

    detail::parallel_for(size, worker);
}

/// \brief Obfuscation stage 2 - parallel version
/// compressed[i] ^= (size - i)
inline void obfuscate_stage2_parallel(std::string& compressed) {
    const size_t size = compressed.size();

    auto worker = [&](size_t start, size_t end) {
        char* p = &compressed[0] + start;
        for (size_t i = start; i < end; ++i, ++p) {
            *p = static_cast<char>(*p ^ (size - i));
        }
    };

    detail::parallel_for(size, worker);
}

/// \brief Obfuscation stage 4 - parallel version
/// output[length-1-i] = encrypted[i] ^ (length - i * length)
inline void obfuscate_stage4_parallel(const std::string& encrypted,
                                      std::string& output) {
    const int length = static_cast<int>(encrypted.size());
    if (length <= 0) {
        output.clear();
        return;
    }

    output.resize(static_cast<size_t>(length));

    auto worker = [&](size_t start, size_t end) {
        int s = static_cast<int>(start);
        int e = static_cast<int>(end);
        for (int i = s; i < e; ++i) {
            int j = length - 1 - i;
            output[static_cast<size_t>(j)] =
                static_cast<char>(encrypted[static_cast<size_t>(i)] ^
                                  (length - i * length));
        }
    };

    detail::parallel_for(static_cast<size_t>(length), worker);
}

// ============================================================================
// CRYPTO
// ============================================================================

/// \brief Decrypt với parallel processing cho các stage
template <typename Algorithm>
inline std::string decrypt(const std::string& input,
                           const std::array<unsigned char, 16>& key,
                           const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string processed;
    std::string output;

    // Stage 1 - deobfuscation (parallel)
    deobfuscate_stage1_parallel(input, processed);

    // Stage 2 - decryption (crypto lib single-thread)
    CryptoPP::StringSource ss(
        processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(
            d, new CryptoPP::StringSink(output)));

    // Stage 3 - deobfuscation (parallel)
    deobfuscate_stage3_parallel(output);

    // Stage 4 - decompression
    return uncompress(
        reinterpret_cast<const unsigned char*>(output.data()),
        static_cast<int>(output.size()));
}

/// \brief Similar to `decrypt`, but with only the first two steps.
template <typename Algorithm>
inline std::string decrypt2(const std::string& input,
                            const std::array<unsigned char, 16>& key,
                            const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string processed;
    std::string output;

    deobfuscate_stage1_parallel(input, processed);

    CryptoPP::StringSource ss(
        processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(
            d, new CryptoPP::StringSink(output)));

    return output;
}

/// \brief Decrypt Packet Tracer file.
inline std::string decrypt_pka(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        137, 137, 137, 137, 137, 137, 137, 137,
        137, 137, 137, 137, 137, 137, 137, 137};
    static const std::array<unsigned char, 16> iv{
        16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16};

    return decrypt<CryptoPP::Twofish>(input, key, iv);
}

inline std::string decrypt_old(std::string input) {
    const size_t size = input.size();

    auto worker = [&](size_t start, size_t end) {
        char* p = &input[0] + start;
        for (size_t i = start; i < end; ++i, ++p) {
            *p = static_cast<char>(*p ^ (size - i));
        }
    };

    detail::parallel_for(size, worker);

    return uncompress(
        reinterpret_cast<const unsigned char*>(input.data()),
        static_cast<int>(input.size()));
}

/// \brief Decrypt logs file.
inline std::string decrypt_logs(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        186, 186, 186, 186, 186, 186, 186, 186,
        186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{
        190, 190, 190, 190, 190, 190, 190, 190,
        190, 190, 190, 190, 190, 190, 190, 190};

    std::string decoded;
    CryptoPP::StringSource ss(
        input, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)));

    return decrypt2<CryptoPP::Twofish>(decoded, key, iv);
}

/// \brief Decrypt file $HOME/packettracer/nets.
inline std::string decrypt_nets(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        186, 186, 186, 186, 186, 186, 186, 186,
        186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{
        190, 190, 190, 190, 190, 190, 190, 190,
        190, 190, 190, 190, 190, 190, 190, 190};

    return decrypt2<CryptoPP::Twofish>(input, key, iv);
}

/// TODO reverse second part of decoding
inline std::string decrypt_sm(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        18, 18, 18, 18, 18, 18, 18, 18,
        18, 18, 18, 18, 18, 18, 18, 18};
    static const std::array<unsigned char, 16> iv{
        254, 254, 254, 254, 254, 254, 254, 254,
        254, 254, 254, 254, 254, 254, 254, 254};

    throw std::runtime_error("unimplemented");

    return decrypt2<CryptoPP::CAST256>(input, key, iv);
}

/// \brief Encrypt với parallel processing
template <typename Algorithm>
inline std::string encrypt(const std::string& input,
                           const std::array<unsigned char, 16>& key,
                           const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    // Stage 1 - compression
    std::string compressed =
        compress(reinterpret_cast<const unsigned char*>(input.data()),
                 static_cast<int>(input.size()));

    // Stage 2 - obfuscation (parallel)
    obfuscate_stage2_parallel(compressed);

    // Stage 3 - encryption
    std::string encrypted;
    CryptoPP::StringSource ss(
        compressed, true,
        new CryptoPP::AuthenticatedEncryptionFilter(
            e, new CryptoPP::StringSink(encrypted)));

    // Stage 4 - obfuscation (parallel)
    std::string output;
    obfuscate_stage4_parallel(encrypted, output);

    return output;
}

/// \brief Similar to encrypt, but skip first two steps
template <typename Algorithm>
inline std::string encrypt2(const std::string& input,
                            const std::array<unsigned char, 16>& key,
                            const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string encrypted;
    CryptoPP::StringSource ss(
        input, true,
        new CryptoPP::AuthenticatedEncryptionFilter(
            e, new CryptoPP::StringSink(encrypted)));

    std::string output;
    obfuscate_stage4_parallel(encrypted, output);

    return output;
}

/// \see decrypt_pka
inline std::string encrypt_pka(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        137, 137, 137, 137, 137, 137, 137, 137,
        137, 137, 137, 137, 137, 137, 137, 137};
    static const std::array<unsigned char, 16> iv{
        16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16};

    return encrypt<CryptoPP::Twofish>(input, key, iv);
}

/// \see decrypt_nets
inline std::string encrypt_nets(const std::string& input) {
    static const std::array<unsigned char, 16> key{
        186, 186, 186, 186, 186, 186, 186, 186,
        186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{
        190, 190, 190, 190, 190, 190, 190, 190,
        190, 190, 190, 190, 190, 190, 190, 190};

    return encrypt2<CryptoPP::Twofish>(input, key, iv);
}

/// \brief Check if PT file was emitted from a Packet Tracer version prior to 5.
inline bool is_old_pt(const std::string& str) {
    // Kiểm tra header zlib (0x78 0x9C) sau khi "gỡ obfuscation" tương ứng
    return (((unsigned char)(str[4] ^ (str.size() - 4)) == 0x78) ||
            ((unsigned char)(str[5] ^ (str.size() - 5)) == 0x9C));
}

/// \brief Tweak pka/pkt file so it can be read by any version of Packet Tracer.
inline std::string fix(std::string input) {
    std::string clear = is_old_pt(input) ? decrypt_old(input)
                                         : decrypt_pka(input);

    re2::RE2::GlobalReplace(
        &clear,
        R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)",
        R"(<VERSION>6.0.1.0000</VERSION>)");
    return encrypt_pka(clear);
}

// ============================================================================
// BATCH PROCESSING - Xử lý nhiều file song song
// ============================================================================

/// \brief Xử lý batch nhiều file PKA song song
/// \param inputs Vector các chuỗi input cần decrypt
/// \param num_threads Số thread sử dụng (0 = auto detect)
/// \return Vector các kết quả đã decrypt
inline std::vector<std::string> decrypt_pka_batch(
    const std::vector<std::string>& inputs,
    size_t num_threads = 0) {

    const size_t total = inputs.size();
    if (total == 0) return {};

    if (num_threads == 0) {
        num_threads = detail::hardware_threads();
    }
    num_threads = std::min(num_threads, total);

    std::vector<std::string> results(total);
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    const size_t chunk_size = (total + num_threads - 1) / num_threads;

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start_idx = t * chunk_size;
        size_t end_idx   = std::min(start_idx + chunk_size, total);

        if (start_idx >= total) break;

        threads.emplace_back(
            [&inputs, &results, start_idx, end_idx]() {
                for (size_t i = start_idx; i < end_idx; ++i) {
                    try {
                        results[i] = decrypt_pka(inputs[i]);
                    } catch (const std::exception& e) {
                        results[i] = "ERROR: " + std::string(e.what());
                    }
                }
            });
    }

    for (auto& th : threads) {
        th.join();
    }

    return results;
}

/// \brief Xử lý batch nhiều file với custom decrypt function
template<typename DecryptFunc>
inline std::vector<std::string> decrypt_batch(
    const std::vector<std::string>& inputs,
    DecryptFunc decrypt_func,
    size_t num_threads = 0) {

    const size_t total = inputs.size();
    if (total == 0) return {};

    if (num_threads == 0) {
        num_threads = detail::hardware_threads();
    }
    num_threads = std::min(num_threads, total);

    std::vector<std::string> results(total);
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    const size_t chunk_size = (total + num_threads - 1) / num_threads;

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start_idx = t * chunk_size;
        size_t end_idx   = std::min(start_idx + chunk_size, total);

        if (start_idx >= total) break;

        threads.emplace_back(
            [&inputs, &results, start_idx, end_idx, decrypt_func]() {
                for (size_t i = start_idx; i < end_idx; ++i) {
                    try {
                        results[i] = decrypt_func(inputs[i]);
                    } catch (const std::exception& e) {
                        results[i] = "ERROR: " + std::string(e.what());
                    }
                }
            });
    }

    for (auto& th : threads) {
        th.join();
    }

    return results;
}

/// \brief Process nhiều file với progress callback
/// \param inputs Vector các input
/// \param decrypt_func Hàm decrypt
/// \param progress_callback Callback nhận (current, total) để báo tiến độ
/// \param num_threads Số threads
template<typename DecryptFunc, typename ProgressCallback>
inline std::vector<std::string> decrypt_batch_with_progress(
    const std::vector<std::string>& inputs,
    DecryptFunc decrypt_func,
    ProgressCallback progress_callback,
    size_t num_threads = 0) {

    const size_t total = inputs.size();
    if (total == 0) return {};

    if (num_threads == 0) {
        num_threads = detail::hardware_threads();
    }
    num_threads = std::min(num_threads, total);

    std::vector<std::string> results(total);
    std::atomic<size_t> completed{0};
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    const size_t chunk_size = (total + num_threads - 1) / num_threads;

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start_idx = t * chunk_size;
        size_t end_idx   = std::min(start_idx + chunk_size, total);

        if (start_idx >= total) break;

        threads.emplace_back(
            [&inputs, &results, &completed,
             start_idx, end_idx, decrypt_func, progress_callback, total]() {
                for (size_t i = start_idx; i < end_idx; ++i) {
                    try {
                        results[i] = decrypt_func(inputs[i]);
                    } catch (const std::exception& e) {
                        results[i] = "ERROR: " + std::string(e.what());
                    }

                    size_t current = ++completed;
                    // Callback phải thread-safe phía caller
                    progress_callback(current, total);
                }
            });
    }

    for (auto& th : threads) {
        th.join();
    }

    return results;
}

}  // namespace pka2xml
