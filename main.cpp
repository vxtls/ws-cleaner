// main.cpp
#include <asio.hpp>
#include <iostream>
#include <string>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <vector>
#include <mutex>
#include <deque>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <csignal>
#include <functional>
#include <condition_variable>
#include <array>
#include <cstring>
#include <iomanip>
#include <cstdlib>
#include <cctype>
#include <arpa/inet.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>

#include "SessionId.hpp"

using asio::ip::tcp;

// ================= Logging =================

static std::shared_ptr<spdlog::logger> g_logger;
static std::atomic<bool> g_use_async_logging{false};

static int parse_log_level_from_env() {
    const char* env = std::getenv("WC_LOG");
    if (!env) return static_cast<int>(spdlog::level::info);
    std::string s(env);
    for (auto &c : s) c = static_cast<char>(std::toupper((unsigned char)c));
    if (s == "TRACE") return static_cast<int>(spdlog::level::trace);
    if (s == "DEBUG") return static_cast<int>(spdlog::level::debug);
    if (s == "INFO")  return static_cast<int>(spdlog::level::info);
    if (s == "WARN")  return static_cast<int>(spdlog::level::warn);
    if (s == "ERROR") return static_cast<int>(spdlog::level::err);
    if (s == "OFF")   return static_cast<int>(spdlog::level::off);
    return static_cast<int>(spdlog::level::info);
}

// Helper function to extract just the filename from full path
static std::string extract_filename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// Initialize logging system
static void init_logging_system() {
    int log_level = parse_log_level_from_env();
    
    // Force synchronous logging to ensure proper file/line display
    g_use_async_logging.store(false);
    g_logger = spdlog::stdout_color_mt("ws-cleaner");
    g_logger->set_level(static_cast<spdlog::level::level_enum>(log_level));
    
    const char* log_env = std::getenv("WC_LOG");
    if (log_env) {
        g_logger->info("Using synchronous logging (WC_LOG={})", log_env);
    } else {
        g_logger->info("Using default synchronous logging (no WC_LOG set)");
    }
    
    // Set log format - file and line will be added by our macros
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%t] [%^%l%$] %v");
}

// Stop logging system
static void shutdown_logging_system() {
    if (g_logger) {
        g_logger->flush();
    }
    spdlog::shutdown();
}

// Enhanced logging macros that include source location
#define LOG_TRACE(...) do { \
    if (g_logger && g_logger->should_log(spdlog::level::trace)) { \
        g_logger->trace("[{}:{}] {}", extract_filename(__FILE__), __LINE__, fmt::format(__VA_ARGS__)); \
    } \
} while(0)

#define LOG_DEBUG(...) do { \
    if (g_logger && g_logger->should_log(spdlog::level::debug)) { \
        g_logger->debug("[{}:{}] {}", extract_filename(__FILE__), __LINE__, fmt::format(__VA_ARGS__)); \
    } \
} while(0)

#define LOG_INFO(...) do { \
    if (g_logger && g_logger->should_log(spdlog::level::info)) { \
        g_logger->info("[{}:{}] {}", extract_filename(__FILE__), __LINE__, fmt::format(__VA_ARGS__)); \
    } \
} while(0)

#define LOG_WARN(...) do { \
    if (g_logger && g_logger->should_log(spdlog::level::warn)) { \
        g_logger->warn("[{}:{}] {}", extract_filename(__FILE__), __LINE__, fmt::format(__VA_ARGS__)); \
    } \
} while(0)

#define LOG_ERROR(...) do { \
    if (g_logger && g_logger->should_log(spdlog::level::err)) { \
        g_logger->error("[{}:{}] {}", extract_filename(__FILE__), __LINE__, fmt::format(__VA_ARGS__)); \
    } \
} while(0)

// ================= Config =================
struct Config {
    struct Server {
        std::string listen_address = "0.0.0.0";
        unsigned short listen_port = 8082;
        std::string target_address = "127.0.0.1";
        unsigned short target_port = 8081;
    } server;
    
    struct RateLimit {
        int max_messages_per_minute = 80;
        int short_window_seconds = 5;
        int short_window_max = 10;
        int long_ban_seconds = 60;
        int short_ban_seconds = 30;
        bool ignore_control_frames = true; // ping/pong/close don't count for rate limit
    } rate_limit;
    
    struct Performance {
        size_t buffer_size = 8192;
        int io_threads = 0;
        int session_cleanup_interval = 300;
        size_t buffer_pool_size = 1024;
        size_t max_websocket_message_size = 16777216; // 16MB
        bool enable_tcp_nodelay = true;
        bool enable_keep_alive = false;
    } performance;
};

class ConfigLoader {
public:
    static Config load(const std::string& filename) {
        Config config;
        try {
            std::ifstream file(filename);
            if (!file.is_open()) {
                LOG_WARN("config {} not found, using defaults", filename);
                return config;
            }
            
            std::string line, section;
            while (std::getline(file, line)) {
                auto first = line.find_first_not_of(" \t\r\n");
                if (first == std::string::npos) continue;
                auto last = line.find_last_not_of(" \t\r\n");
                line = line.substr(first, last - first + 1);
                if (line.empty() || line[0] == '#' || line[0] == ';') continue;
                
                if (line.front() == '[' && line.back() == ']') {
                    section = line.substr(1, line.size() - 2);
                    continue;
                }
                
                auto delim = line.find('=');
                if (delim == std::string::npos) continue;
                std::string key = line.substr(0, delim);
                std::string value = line.substr(delim + 1);
                
                // Trim whitespace
                auto kf = key.find_first_not_of(" \t");
                auto kl = key.find_last_not_of(" \t");
                key = key.substr(kf, kl - kf + 1);
                auto vf = value.find_first_not_of(" \t");
                auto vl = value.find_last_not_of(" \t");
                value = value.substr(vf, vl - vf + 1);
                
                parse_config_value(section, key, value, config);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error loading config: {} - using defaults", e.what());
        }
        return config;
    }
    
private:
    static void parse_config_value(const std::string& section, const std::string& key,
                                   const std::string& value, Config& config) {
        try {
            if (section == "server") {
                if (key == "listen_address") config.server.listen_address = value;
                else if (key == "listen_port") config.server.listen_port = static_cast<unsigned short>(std::stoi(value));
                else if (key == "target_address") config.server.target_address = value;
                else if (key == "target_port") config.server.target_port = static_cast<unsigned short>(std::stoi(value));
            } else if (section == "rate_limit") {
                if (key == "max_messages_per_minute") config.rate_limit.max_messages_per_minute = std::stoi(value);
                else if (key == "short_window_seconds") config.rate_limit.short_window_seconds = std::stoi(value);
                else if (key == "short_window_max") config.rate_limit.short_window_max = std::stoi(value);
                else if (key == "long_ban_seconds") config.rate_limit.long_ban_seconds = std::stoi(value);
                else if (key == "short_ban_seconds") config.rate_limit.short_ban_seconds = std::stoi(value);
                else if (key == "ignore_control_frames") config.rate_limit.ignore_control_frames = (value == "true" || value == "1");
            } else if (section == "performance") {
                if (key == "buffer_size") config.performance.buffer_size = static_cast<size_t>(std::stoul(value));
                else if (key == "io_threads") config.performance.io_threads = std::stoi(value);
                else if (key == "session_cleanup_interval") config.performance.session_cleanup_interval = std::stoi(value);
                else if (key == "buffer_pool_size") config.performance.buffer_pool_size = static_cast<size_t>(std::stoul(value));
                else if (key == "max_websocket_message_size") config.performance.max_websocket_message_size = static_cast<size_t>(std::stoul(value));
                else if (key == "enable_tcp_nodelay") config.performance.enable_tcp_nodelay = (value == "true" || value == "1");
                else if (key == "enable_keep_alive") config.performance.enable_keep_alive = (value == "true" || value == "1");
            }
        } catch (...) {
                LOG_WARN("Config parse warning for {} value={}", key, value);
        }
    }
};

// ================= Stats =================
static std::atomic<uint64_t> g_active_sessions{0};
static std::atomic<uint64_t> g_total_websocket_messages{0};
static std::atomic<uint64_t> g_total_control_frames{0};
static std::atomic<uint64_t> g_total_dropped_messages{0};
static std::atomic<uint64_t> g_total_banned_sessions{0};
static std::atomic<uint64_t> g_total_bytes_client_to_server{0};
static std::atomic<uint64_t> g_total_bytes_server_to_client{0};

// Periodic stats logging (every 5 minutes)
static std::chrono::steady_clock::time_point g_last_stats_log = std::chrono::steady_clock::now();
static constexpr int STATS_LOG_INTERVAL_SECONDS = 300;

static void maybe_log_periodic_stats() {
    auto now = std::chrono::steady_clock::now();
    if (now - g_last_stats_log >= std::chrono::seconds(STATS_LOG_INTERVAL_SECONDS)) {
        g_last_stats_log = now;
        LOG_INFO("PERIODIC_STATS active_sessions={} total_ws_messages={} control_frames={} dropped_messages={} banned_sessions={} bytes_c2s={} bytes_s2c={}",
                 g_active_sessions.load(),
                 g_total_websocket_messages.load(),
                 g_total_control_frames.load(),
                 g_total_dropped_messages.load(),
                 g_total_banned_sessions.load(),
                 g_total_bytes_client_to_server.load(),
                 g_total_bytes_server_to_client.load());
    }
}

// ================= BufferPool =================
class BufferPool {
public:
    using Buffer = std::vector<char>;
    using Ptr = std::shared_ptr<Buffer>;
    
    BufferPool(size_t pool_size, size_t buffer_size) : buf_size_(buffer_size) {
        buffers_.reserve(pool_size);
        for (size_t i = 0; i < pool_size; ++i) {
            buffers_.push_back(std::make_shared<Buffer>(buf_size_));
        }
    }
    
    Ptr get() {
        std::lock_guard<std::mutex> lk(m_);
        if (buffers_.empty()) {
            return std::make_shared<Buffer>(buf_size_);
        }
        auto p = buffers_.back();
        buffers_.pop_back();
        return p;
    }
    
    void put(Ptr p) {
        if (!p) return;
        std::lock_guard<std::mutex> lk(m_);
        if (p->capacity() < buf_size_) p->reserve(buf_size_);
        p->clear(); // Reset size but keep capacity
        buffers_.push_back(std::move(p));
    }
    
private:
    std::mutex m_;
    std::vector<Ptr> buffers_;
    size_t buf_size_;
};

// ================= TokenBucket =================
class TokenBucket {
public:
    TokenBucket(double rate_per_sec = 1.0, double burst = 1.0)
        : rate_(rate_per_sec), burst_(std::max(1.0, burst)), tokens_(burst_), 
          last_(std::chrono::steady_clock::now()) {}
    
    bool try_consume(double amount = 1.0) {
        std::lock_guard<std::mutex> lk(m_);
        refill_unlocked();
        if (tokens_ + 1e-9 < amount) return false;
        tokens_ -= amount;
        return true;
    }
    
    void refund(double amount = 1.0) {
        std::lock_guard<std::mutex> lk(m_);
        refill_unlocked();
        tokens_ = std::min(burst_, tokens_ + amount);
    }
    
    double available_tokens() {
        std::lock_guard<std::mutex> lk(m_);
        refill_unlocked();
        return tokens_;
    }
    
private:
    void refill_unlocked() {
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - last_).count();
        if (dt > 0) {
            tokens_ = std::min(burst_, tokens_ + dt * rate_);
            last_ = now;
        }
    }
    
    double rate_, burst_, tokens_;
    std::chrono::steady_clock::time_point last_;
    std::mutex m_;
};

// ================= RateLimiter =================
class RateLimiter {
public:
    struct SessionData {
        TokenBucket short_tb;
        TokenBucket long_tb;
        std::chrono::steady_clock::time_point last_activity;
        std::chrono::steady_clock::time_point ban_until;
        std::atomic<bool> is_banned{false};
        std::atomic<uint32_t> message_count{0}; // Total messages from this session
        
        SessionData(double short_rate, double short_burst, double long_rate, double long_burst)
            : short_tb(short_rate, short_burst), long_tb(long_rate, long_burst),
              last_activity(std::chrono::steady_clock::now()),
              ban_until(std::chrono::steady_clock::time_point::min()) {}
    };

    static constexpr int SHARDS = 32; // Increased for better concurrency
    
    RateLimiter(int short_window_seconds, int short_window_max,
                int long_window_seconds, int long_window_max,
                int cleanup_interval_seconds,
                int short_ban_seconds = 30,
                int long_ban_seconds = 60)
        : cleanup_interval_(cleanup_interval_seconds),
          short_ban_duration_(short_ban_seconds),
          long_ban_duration_(long_ban_seconds)
    {
        short_rate_per_sec_ = static_cast<double>(short_window_max) / std::max(1, short_window_seconds);
        short_burst_ = static_cast<double>(short_window_max);
        long_rate_per_sec_ = static_cast<double>(long_window_max) / std::max(1, long_window_seconds);
        long_burst_ = static_cast<double>(long_window_max);
        
        running_.store(true);
        cleanup_thread_ = std::thread([this]{ cleanup_loop(); });
        
        LOG_INFO("RateLimiter initialized: short={}/{}s (ban {}s), long={}/{}s (ban {}s)", 
                 short_window_max, short_window_seconds, short_ban_seconds, 
                 long_window_max, long_window_seconds, long_ban_seconds);
    }

    ~RateLimiter() {
        running_.store(false);
        cv_.notify_one();
        if (cleanup_thread_.joinable()) cleanup_thread_.join();
    }

    enum class ConsumeResult {
        ALLOWED,
        DENIED_RATE_LIMIT_SHORT,
        DENIED_RATE_LIMIT_LONG,
        DENIED_BANNED
    };

    // Main rate limiting function for WebSocket messages
    ConsumeResult consume_websocket_message(const std::string& session_id, uint8_t opcode, size_t payload_size) {
        size_t si = std::hash<std::string>{}(session_id) % SHARDS;
        std::lock_guard<std::mutex> lk(shard_mutexes_[si]);
        
        auto &m = shards_[si];
        auto it = m.find(session_id);
        if (it == m.end()) {
            it = m.emplace(session_id, std::make_shared<SessionData>(
                short_rate_per_sec_, short_burst_, long_rate_per_sec_, long_burst_)).first;
        }
        
        auto sd = it->second;
        auto now = std::chrono::steady_clock::now();
        sd->last_activity = now;

        // Check if currently banned
        if (sd->is_banned.load(std::memory_order_relaxed)) {
            if (now >= sd->ban_until) {
                // Ban expired, unban the session
                sd->is_banned.store(false, std::memory_order_relaxed);
                sd->ban_until = std::chrono::steady_clock::time_point::min();
                LOG_INFO("Session {} auto-unbanned (ban period expired)", session_id);
            } else {
                return ConsumeResult::DENIED_BANNED;
            }
        }

        // Only rate limit data frames (text/binary), not control frames
        bool is_control_frame = (opcode & 0x08) != 0;
        if (is_control_frame) {
            g_total_control_frames.fetch_add(1, std::memory_order_relaxed);
            return ConsumeResult::ALLOWED; // Control frames don't count against rate limit
        }

        sd->message_count.fetch_add(1, std::memory_order_relaxed);

        // Short window check (priority)
        if (!sd->short_tb.try_consume(1.0)) {
            ban_session_unlocked(sd, session_id, short_ban_duration_, "short window rate limit");
            return ConsumeResult::DENIED_RATE_LIMIT_SHORT;
        }
        
        // Long window check
        if (!sd->long_tb.try_consume(1.0)) {
            sd->short_tb.refund(1.0); // Refund the short window token
            ban_session_unlocked(sd, session_id, long_ban_duration_, "long window rate limit");
            return ConsumeResult::DENIED_RATE_LIMIT_LONG;
        }
        
        return ConsumeResult::ALLOWED;
    }

    bool is_session_banned(const std::string& session_id) {
        size_t si = std::hash<std::string>{}(session_id) % SHARDS;
        std::lock_guard<std::mutex> lk(shard_mutexes_[si]);
        
        auto &m = shards_[si];
        auto it = m.find(session_id);
        if (it == m.end()) return false;
        
        auto sd = it->second;
        auto now = std::chrono::steady_clock::now();
        
        if (sd->is_banned.load(std::memory_order_relaxed) && now >= sd->ban_until) {
            // Ban expired
            sd->is_banned.store(false, std::memory_order_relaxed);
            sd->ban_until = std::chrono::steady_clock::time_point::min();
            LOG_DEBUG("Session {} auto-unbanned during status check", session_id);
            return false;
        }
        
        return sd->is_banned.load(std::memory_order_relaxed);
    }

    void remove_session(const std::string& session_id) {
        size_t si = std::hash<std::string>{}(session_id) % SHARDS;
        std::lock_guard<std::mutex> lk(shard_mutexes_[si]);
        shards_[si].erase(session_id);
    }

    // Get statistics for a specific session
    struct SessionStats {
        uint32_t message_count;
        double short_tokens_available;
        double long_tokens_available;
        bool is_banned;
        std::chrono::seconds ban_remaining{0};
    };
    
    std::optional<SessionStats> get_session_stats(const std::string& session_id) {
        size_t si = std::hash<std::string>{}(session_id) % SHARDS;
        std::lock_guard<std::mutex> lk(shard_mutexes_[si]);
        
        auto &m = shards_[si];
        auto it = m.find(session_id);
        if (it == m.end()) return std::nullopt;
        
        auto sd = it->second;
        auto now = std::chrono::steady_clock::now();
        
        SessionStats stats;
        stats.message_count = sd->message_count.load(std::memory_order_relaxed);
        stats.short_tokens_available = sd->short_tb.available_tokens();
        stats.long_tokens_available = sd->long_tb.available_tokens();
        stats.is_banned = sd->is_banned.load(std::memory_order_relaxed);
        
        if (stats.is_banned && sd->ban_until > now) {
            stats.ban_remaining = std::chrono::duration_cast<std::chrono::seconds>(sd->ban_until - now);
        }
        
        return stats;
    }

private:
    void ban_session_unlocked(std::shared_ptr<SessionData> sd, const std::string& session_id, 
                             int duration_seconds, const std::string& reason) {
        auto now = std::chrono::steady_clock::now();
        sd->is_banned.store(true, std::memory_order_relaxed);
        sd->ban_until = now + std::chrono::seconds(duration_seconds);
        g_total_banned_sessions.fetch_add(1, std::memory_order_relaxed);
        
        LOG_WARN("Session {} BANNED for {} seconds (reason: {}, messages sent: {})", 
                 session_id, duration_seconds, reason, 
                 sd->message_count.load(std::memory_order_relaxed));
    }

    void cleanup_loop() {
        std::unique_lock<std::mutex> lk(cv_m_);
        while (running_.load()) {
            cv_.wait_for(lk, std::chrono::seconds(cleanup_interval_));
            if (!running_.load()) break;
            
            auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(15); // Longer retention
            auto now = std::chrono::steady_clock::now();
            int cleaned = 0;
            int unbanned = 0;
            
            for (int i = 0; i < SHARDS; ++i) {
                std::lock_guard<std::mutex> lk2(shard_mutexes_[i]);
                auto &m = shards_[i];
                for (auto it = m.begin(); it != m.end();) {
                    auto sd = it->second;
                    
                    // Auto-unban expired bans
                    if (sd->is_banned.load(std::memory_order_relaxed) && now >= sd->ban_until) {
                        sd->is_banned.store(false, std::memory_order_relaxed);
                        sd->ban_until = std::chrono::steady_clock::time_point::min();
                        LOG_DEBUG("Session {} auto-unbanned during cleanup", it->first);
                        unbanned++;
                    }
                    
                    // Remove old inactive sessions (but keep recently banned ones)
                    if (!sd->is_banned.load(std::memory_order_relaxed) && sd->last_activity < cutoff) {
                        it = m.erase(it);
                        cleaned++;
                    } else {
                        ++it;
                    }
                }
            }
            
            if (cleaned > 0 || unbanned > 0) {
                LOG_DEBUG("Cleanup: removed {} old sessions, unbanned {} expired bans", cleaned, unbanned);
            }
            
            maybe_log_periodic_stats();
        }
    }

    std::array<std::unordered_map<std::string, std::shared_ptr<SessionData>>, SHARDS> shards_;
    std::array<std::mutex, SHARDS> shard_mutexes_;
    std::atomic<bool> running_{false};
    std::thread cleanup_thread_;
    std::condition_variable cv_;
    std::mutex cv_m_;
    int cleanup_interval_;
    int short_ban_duration_;
    int long_ban_duration_;
    double short_rate_per_sec_{0}, short_burst_{1}, long_rate_per_sec_{0}, long_burst_{1};
};

// ================= WebSocket Frame Parser =================
class WebSocketFrameParser {
public:
    using MessageStartCallback = std::function<bool(uint8_t opcode, size_t estimated_payload_size)>;
    using MessageCompleteCallback = std::function<void(std::vector<char>&& payload, uint8_t opcode, bool is_final)>;

    WebSocketFrameParser() { 
        max_msg_size_ = 16 * 1024 * 1024; 
        reset(); 
    }
    
    void set_max_message_size(size_t n) { max_msg_size_ = n; }

    void feed(const char* data, size_t len, 
              const MessageStartCallback& on_message_start, 
              const MessageCompleteCallback& on_message_complete) {
        
        input_buffer_.insert(input_buffer_.end(), data, data + len);
        parse_frames(on_message_start, on_message_complete);
    }
    
    bool was_denied() const { return denied_; }
    void reset_denied() { denied_ = false; }
    size_t frames_parsed() const { return frames_parsed_; }

private:
    void reset() { 
        input_buffer_.clear(); 
        current_message_.clear(); 
        in_fragmented_message_ = false; 
        current_opcode_ = 0;
        denied_ = false; 
        frames_parsed_ = 0;
    }

    void parse_frames(const MessageStartCallback& on_start, const MessageCompleteCallback& on_complete) {
        while (input_buffer_.size() >= 2) {
            uint8_t b0 = static_cast<uint8_t>(input_buffer_[0]);
            uint8_t b1 = static_cast<uint8_t>(input_buffer_[1]);
            
            bool fin = (b0 & 0x80) != 0;
            uint8_t opcode = b0 & 0x0f;
            bool masked = (b1 & 0x80) != 0;
            uint64_t payload_len = (b1 & 0x7f);
            size_t header_len = 2;

            // Extended payload length
            if (payload_len == 126) {
                if (input_buffer_.size() < header_len + 2) return;
                payload_len = (static_cast<uint16_t>(input_buffer_[2]) << 8) | 
                             static_cast<uint8_t>(input_buffer_[3]);
                header_len += 2;
            } else if (payload_len == 127) {
                if (input_buffer_.size() < header_len + 8) return;
                payload_len = 0;
                for (int i = 0; i < 8; ++i) {
                    payload_len = (payload_len << 8) | static_cast<uint8_t>(input_buffer_[2 + i]);
                }
                header_len += 8;
            }

            // Masking key
            uint8_t mask[4] = {0, 0, 0, 0};
            if (masked) {
                if (input_buffer_.size() < header_len + 4) return;
                for (int i = 0; i < 4; ++i) {
                    mask[i] = static_cast<uint8_t>(input_buffer_[header_len + i]);
                }
                header_len += 4;
            }

            // Check if we have the complete frame
            if (input_buffer_.size() < header_len + payload_len) return;
            
            // Validate message size
            if (payload_len > max_msg_size_) {
                throw std::runtime_error("WebSocket message too large: " + std::to_string(payload_len));
            }

            frames_parsed_++;
            
            // Handle control frames vs data frames
            if ((opcode & 0x8) != 0) {
                // Control frame (ping/pong/close) - process immediately, don't rate limit
                if (on_start && !on_start(opcode, static_cast<size_t>(payload_len))) {
                    denied_ = true;
                    return;
                }
                
                std::vector<char> control_payload;
                if (payload_len > 0) {
                    control_payload.reserve(static_cast<size_t>(payload_len));
                    size_t payload_start = header_len;
                    for (size_t i = 0; i < payload_len; ++i) {
                        char c = input_buffer_[payload_start + i];
                        if (masked) c = static_cast<char>(c ^ mask[i & 0x3]);
                        control_payload.push_back(c);
                    }
                }
                
                if (on_complete) {
                    on_complete(std::move(control_payload), opcode, true);
                }
            } else {
                // Data frame (text/binary/continuation)
                bool is_message_start = (opcode == 0x1 || opcode == 0x2); // text or binary
                bool is_continuation = (opcode == 0x0);
                
                if (is_message_start && !in_fragmented_message_) {
                    // Start of new message
                    current_opcode_ = opcode;
                    if (on_start && !on_start(opcode, static_cast<size_t>(payload_len))) {
                        denied_ = true;
                        return;
                    }
                    in_fragmented_message_ = true;
                    current_message_.clear();
                } else if (is_continuation && in_fragmented_message_) {
                    // Continuation of existing message - no rate limit check needed
                } else {
                    // Invalid frame sequence
                    throw std::runtime_error("Invalid WebSocket frame sequence");
                }
                
                // Accumulate payload data
                if (payload_len > 0) {
                    size_t payload_start = header_len;
                    size_t old_size = current_message_.size();
                    current_message_.resize(old_size + static_cast<size_t>(payload_len));
                    
                    for (size_t i = 0; i < payload_len; ++i) {
                        char c = input_buffer_[payload_start + i];
                        if (masked) c = static_cast<char>(c ^ mask[i & 0x3]);
                        current_message_[old_size + i] = c;
                    }
                }
                
                // Check if message is complete
                if (fin) {
                    if (on_complete) {
                        on_complete(std::move(current_message_), current_opcode_, true);
                    }
                    current_message_.clear();
                    in_fragmented_message_ = false;
                    current_opcode_ = 0;
                }
            }

            // Remove processed frame from buffer
            input_buffer_.erase(input_buffer_.begin(), 
                               input_buffer_.begin() + header_len + static_cast<size_t>(payload_len));
        }
    }

    std::vector<char> input_buffer_;
    std::vector<char> current_message_;
    size_t max_msg_size_;
    bool in_fragmented_message_;
    uint8_t current_opcode_;
    bool denied_;
    size_t frames_parsed_;
};

// ================= WebSocketSession =================
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    using BufferPtr = std::shared_ptr<std::vector<char>>;

    WebSocketSession(tcp::socket client_sock,
                     asio::io_context& ioc,
                     std::shared_ptr<tcp::socket> server_sock,
                     std::shared_ptr<RateLimiter> rate_limiter,
                     std::shared_ptr<BufferPool> pool,
                     std::string session_id,
                     const Config& config)
        : client_socket_(std::move(client_sock)),
          io_context_(ioc),
          server_socket_shared_(server_sock),
          server_socket_(*server_sock),
          rate_limiter_(rate_limiter),
          buffer_pool_(pool),
          strand_(asio::make_strand(ioc)),
          session_id_(std::move(session_id)),
          config_(config),
          state_(State::Handshaking)
    {
        g_active_sessions.fetch_add(1, std::memory_order_relaxed);
        parser_.set_max_message_size(config_.performance.max_websocket_message_size);
        LOG_DEBUG("Session created: {} (active: {})", session_id_, g_active_sessions.load());
    }

    ~WebSocketSession() {
        LOG_DEBUG("Session destroyed: {} (frames parsed: {})", session_id_, parser_.frames_parsed());
    }

    void start() { 
        // Check if session is banned before starting
        if (rate_limiter_->is_session_banned(session_id_)) {
            LOG_INFO("Rejecting connection from banned session: {}", session_id_);
            send_close_and_stop(1008, "Session banned");
            return;
        }
        
        LOG_DEBUG("Starting session: {}", session_id_);
        do_read_client(); 
        do_read_server(); 
    }

private:
    enum class State { Handshaking, Open, Closing, Closed };
    
    State state_;
    std::string client_http_buffer_;
    std::string server_http_buffer_;
    bool client_handshake_done_ = false;
    bool server_handshake_done_ = false;
    const Config& config_;

    void do_read_client() {
        if (state_ == State::Closed) return;
        
        auto self = shared_from_this();
        auto buf = buffer_pool_->get();
        
        client_socket_.async_read_some(asio::buffer(*buf),
            asio::bind_executor(strand_, [this, self, buf](std::error_code ec, std::size_t bytes_read) mutable {
                if (ec) { 
                    LOG_DEBUG("Client read error {}: {}", session_id_, ec.message()); 
                    cleanup(); 
                    buffer_pool_->put(buf);
                    return; 
                }
                
                g_total_bytes_client_to_server.fetch_add(bytes_read, std::memory_order_relaxed);
                
                if (state_ == State::Handshaking) {
                    handle_handshake_client_data(buf->data(), bytes_read);
                    async_write_to_server(buf, bytes_read);
                } else if (state_ == State::Open) {
                    handle_websocket_client_data(buf->data(), bytes_read);
                } else {
                    // In closing/closed state, just forward data without processing
                    async_write_to_server(buf, bytes_read);
                }
                
                // Continue reading unless we're in an error state
                if (state_ != State::Closed) {
                    do_read_client();
                } else {
                    buffer_pool_->put(buf);
                }
            })
        );
    }

    void do_read_server() {
        if (state_ == State::Closed) return;
        
        auto self = shared_from_this();
        auto buf = buffer_pool_->get();
        
        server_socket_.async_read_some(asio::buffer(*buf),
            asio::bind_executor(strand_, [this, self, buf](std::error_code ec, std::size_t bytes_read) mutable {
                if (ec) { 
                    LOG_DEBUG("Server read error {}: {}", session_id_, ec.message()); 
                    cleanup(); 
                    buffer_pool_->put(buf);
                    return; 
                }
                
                g_total_bytes_server_to_client.fetch_add(bytes_read, std::memory_order_relaxed);
                
                if (state_ == State::Handshaking) {
                    handle_handshake_server_data(buf->data(), bytes_read);
                }
                
                // Always forward server data to client
                async_write_to_client(buf, bytes_read);
                
                // Continue reading unless we're in an error state
                if (state_ != State::Closed) {
                    do_read_server();
                } else {
                    buffer_pool_->put(buf);
                }
            })
        );
    }

    void handle_handshake_client_data(const char* data, size_t len) {
        client_http_buffer_.append(data, len);
        
        if (!client_handshake_done_) {
            auto pos = client_http_buffer_.find("\r\n\r\n");
            if (pos != std::string::npos) {
                client_handshake_done_ = true;
                LOG_TRACE("Client handshake completed: {}", session_id_);
                maybe_complete_handshake();
            }
        }
    }

    void handle_handshake_server_data(const char* data, size_t len) {
        server_http_buffer_.append(data, len);
        
        if (!server_handshake_done_) {
            auto pos = server_http_buffer_.find("\r\n\r\n");
            if (pos != std::string::npos) {
                // Check for 101 Switching Protocols response
                if (server_http_buffer_.find(" 101 ") != std::string::npos || 
                    server_http_buffer_.find(" 101\r\n") != std::string::npos) {
                    server_handshake_done_ = true;
                    LOG_TRACE("Server handshake completed: {}", session_id_);
                    maybe_complete_handshake();
                } else {
                    LOG_WARN("WebSocket handshake failed for session: {}", session_id_);
                    cleanup();
                    return;
                }
            }
        }
    }

    void handle_websocket_client_data(const char* data, size_t len) {
        parser_.reset_denied();
        
        try {
            parser_.feed(data, len,
                // Message start callback - called once per WebSocket message (not per frame)
                [this](uint8_t opcode, size_t estimated_size) -> bool {
                    LOG_TRACE("WebSocket message start: session={} opcode={} est_size={}", 
                             session_id_, (int)opcode, estimated_size);
                    
                    auto result = rate_limiter_->consume_websocket_message(session_id_, opcode, estimated_size);
                    
                    switch (result) {
                        case RateLimiter::ConsumeResult::ALLOWED:
                            g_total_websocket_messages.fetch_add(1, std::memory_order_relaxed);
                            return true;
                            
                        case RateLimiter::ConsumeResult::DENIED_RATE_LIMIT_SHORT:
                            g_total_dropped_messages.fetch_add(1, std::memory_order_relaxed);
                            LOG_INFO("SHORT rate limit exceeded: session={} opcode={} - session banned", 
                                   session_id_, (int)opcode);
                            return false;
                            
                        case RateLimiter::ConsumeResult::DENIED_RATE_LIMIT_LONG:
                            g_total_dropped_messages.fetch_add(1, std::memory_order_relaxed);
                            LOG_INFO("LONG rate limit exceeded: session={} opcode={} - session banned", 
                                   session_id_, (int)opcode);
                            return false;
                            
                        case RateLimiter::ConsumeResult::DENIED_BANNED:
                            g_total_dropped_messages.fetch_add(1, std::memory_order_relaxed);
                            LOG_DEBUG("Message from banned session: {} opcode={}", session_id_, (int)opcode);
                            return false;
                            
                        default:
                            return false;
                    }
                },
                
                // Message complete callback
                [this](std::vector<char>&& payload, uint8_t opcode, bool is_final) {
                    LOG_TRACE("WebSocket message complete: session={} opcode={} size={} final={}", 
                             session_id_, (int)opcode, payload.size(), is_final);
                    
                    // Message processing could be added here if needed
                    // For now, we just log the completion
                }
            );
            
        } catch (const std::exception& e) {
            LOG_WARN("WebSocket parsing error for session {}: {}", session_id_, e.what());
            send_close_and_stop(1002, "Protocol error");
            return;
        }
        
        // Check if the parser denied a message (rate limit exceeded)
        if (parser_.was_denied()) {
            LOG_INFO("WebSocket message denied for session {} - sending close frame", session_id_);
            send_close_and_stop(1008, "Rate limit exceeded");
            return;
        }
        
        // Forward the raw data to server (whether allowed or not, let server handle it)
        auto buf_copy = buffer_pool_->get();
        buf_copy->assign(data, data + len);
        async_write_to_server(buf_copy, len);
    }

    void maybe_complete_handshake() {
        if (client_handshake_done_ && server_handshake_done_) {
            state_ = State::Open;
            LOG_INFO("WebSocket connection established: {}", session_id_);
            
            // Clear handshake buffers to free memory
            client_http_buffer_.clear();
            client_http_buffer_.shrink_to_fit();
            server_http_buffer_.clear();
            server_http_buffer_.shrink_to_fit();
        }
    }

    void async_write_to_server(const BufferPtr& buf, std::size_t len) {
        if (state_ == State::Closed) {
            buffer_pool_->put(buf);
            return;
        }
        
        auto self = shared_from_this();
        asio::async_write(server_socket_, asio::buffer(buf->data(), len),
            asio::bind_executor(strand_, [this, self, buf](std::error_code ec, std::size_t) {
                buffer_pool_->put(buf);
                if (ec) { 
                    LOG_DEBUG("Server write error {}: {}", session_id_, ec.message()); 
                    cleanup(); 
                }
            })
        );
    }
    
    void async_write_to_client(const BufferPtr& buf, std::size_t len) {
        if (state_ == State::Closed) {
            buffer_pool_->put(buf);
            return;
        }
        
        auto self = shared_from_this();
        asio::async_write(client_socket_, asio::buffer(buf->data(), len),
            asio::bind_executor(strand_, [this, self, buf](std::error_code ec, std::size_t) {
                buffer_pool_->put(buf);
                if (ec) { 
                    LOG_DEBUG("Client write error {}: {}", session_id_, ec.message()); 
                    cleanup(); 
                }
            })
        );
    }

    void send_close_and_stop(uint16_t code, const std::string& reason) {
        if (state_ == State::Closed || state_ == State::Closing) return;
        
        state_ = State::Closing;
        LOG_DEBUG("Sending WebSocket close frame: session={} code={} reason={}", 
                 session_id_, code, reason);
        
        // Build WebSocket close frame
        std::vector<char> payload;
        payload.resize(2 + reason.size());
        uint16_t network_code = htons(code);
        std::memcpy(payload.data(), &network_code, 2);
        std::memcpy(payload.data() + 2, reason.data(), reason.size());
        
        std::vector<char> frame;
        frame.push_back(static_cast<char>(0x88)); // FIN + Close opcode
        
        if (payload.size() < 126) {
            frame.push_back(static_cast<char>(payload.size()));
        } else {
            frame.push_back(126);
            uint16_t len = htons(static_cast<uint16_t>(payload.size()));
            frame.insert(frame.end(), reinterpret_cast<char*>(&len), reinterpret_cast<char*>(&len) + 2);
        }
        
        frame.insert(frame.end(), payload.begin(), payload.end());
        
        auto frame_buffer = std::make_shared<std::vector<char>>(std::move(frame));
        auto self = shared_from_this();
        
        asio::async_write(client_socket_, asio::buffer(*frame_buffer),
            asio::bind_executor(strand_, [this, self, frame_buffer](std::error_code /*ec*/, std::size_t /*bytes*/) {
                LOG_TRACE("Close frame sent to session: {}", session_id_);
                cleanup();
            })
        );
    }

    void cleanup() {
        if (state_ == State::Closed) return;
        
        LOG_DEBUG("Cleaning up session: {}", session_id_);
        state_ = State::Closed;
        
        std::error_code ec;
        
        // Cancel any pending asynchronous operations
        client_socket_.cancel(ec);
        if (ec) LOG_TRACE("Client socket cancel error: {}", ec.message());
        
        server_socket_.cancel(ec);
        if (ec) LOG_TRACE("Server socket cancel error: {}", ec.message());
        
        // Close the sockets
        if (client_socket_.is_open()) {
            client_socket_.close(ec);
            if (ec) LOG_TRACE("Client socket close error: {}", ec.message());
        }
        if (server_socket_.is_open()) {
            server_socket_.close(ec);
            if (ec) LOG_TRACE("Server socket close error: {}", ec.message());
        }
        
        if (rate_limiter_) {
            rate_limiter_->remove_session(session_id_);
        }
        
        g_active_sessions.fetch_sub(1, std::memory_order_relaxed);
        LOG_DEBUG("Session cleanup completed: {} (active: {})", session_id_, g_active_sessions.load());
    }

    tcp::socket client_socket_;
    asio::io_context& io_context_;
    std::shared_ptr<tcp::socket> server_socket_shared_;
    tcp::socket& server_socket_;
    std::shared_ptr<RateLimiter> rate_limiter_;
    std::shared_ptr<BufferPool> buffer_pool_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::string session_id_;
    WebSocketFrameParser parser_;
};

// ================= WebSocketProxy =================
class WebSocketProxy {
public:
    WebSocketProxy(asio::io_context& ioc, const Config& cfg)
        : io_context_(ioc),
          acceptor_(ioc),
          resolver_(ioc),
          config_(cfg),
          rate_limiter_(std::make_shared<RateLimiter>(
              cfg.rate_limit.short_window_seconds,
              cfg.rate_limit.short_window_max,
              60, // Long window is always 60 seconds
              cfg.rate_limit.max_messages_per_minute,
              cfg.performance.session_cleanup_interval,
              cfg.rate_limit.short_ban_seconds,
              cfg.rate_limit.long_ban_seconds)),
          buffer_pool_(std::make_shared<BufferPool>(cfg.performance.buffer_pool_size, cfg.performance.buffer_size))
    {
        setup_acceptor();
        log_configuration();
        start_accepting();
    }

private:
    void setup_acceptor() {
        asio::ip::address addr = asio::ip::make_address(config_.server.listen_address);
        tcp::endpoint endpoint(addr, config_.server.listen_port);
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::socket_base::reuse_address(true));
        
        if (config_.performance.enable_keep_alive) {
            acceptor_.set_option(asio::socket_base::keep_alive(true));
        }
        
        acceptor_.bind(endpoint);
        acceptor_.listen();
    }
    
    void log_configuration() {
        LOG_INFO("WebSocket Proxy Configuration:");
        LOG_INFO("  Listen: {}:{}", config_.server.listen_address, config_.server.listen_port);
        LOG_INFO("  Target: {}:{}", config_.server.target_address, config_.server.target_port);
        LOG_INFO("  Rate Limits:");
        LOG_INFO("    Short: {} per {}s (ban {}s)", config_.rate_limit.short_window_max, 
                config_.rate_limit.short_window_seconds, config_.rate_limit.short_ban_seconds);
        LOG_INFO("    Long:  {} per 60s (ban {}s)", config_.rate_limit.max_messages_per_minute, 
                config_.rate_limit.long_ban_seconds);
        LOG_INFO("  Performance:");
        LOG_INFO("    Buffer size: {} bytes", config_.performance.buffer_size);
        LOG_INFO("    Buffer pool: {} buffers", config_.performance.buffer_pool_size);
        LOG_INFO("    Max WS message: {} bytes", config_.performance.max_websocket_message_size);
        LOG_INFO("    TCP nodelay: {}", (config_.performance.enable_tcp_nodelay ? "enabled" : "disabled"));
    }

    void start_accepting() {
        acceptor_.async_accept([this](std::error_code ec, tcp::socket client_socket) {
            if (!ec) {
                handle_new_connection(std::move(client_socket));
            } else {
                LOG_WARN("Accept error: {}", ec.message());
            }
            
            // Continue accepting new connections
            start_accepting();
        });
    }

    void handle_new_connection(tcp::socket client_socket) {
        try {
            std::string session_id = randomidgen::make_session_id();
            
            // Configure client socket
            if (config_.performance.enable_tcp_nodelay) {
                client_socket.set_option(tcp::no_delay(true));
            }
            if (config_.performance.enable_keep_alive) {
                client_socket.set_option(asio::socket_base::keep_alive(true));
            }
            
            LOG_DEBUG("New connection accepted: {}", session_id);
            
            // Resolve target server
            resolver_.async_resolve(config_.server.target_address,
                                   std::to_string(config_.server.target_port),
                [this, session_id, client_socket = std::move(client_socket)]
                (std::error_code ec, tcp::resolver::results_type results) mutable {
                    
                    if (ec) { 
                        LOG_WARN("DNS resolution failed for {}: {}", config_.server.target_address, ec.message());
                        return; 
                    }
                    
                    connect_to_target(std::move(client_socket), session_id, results);
                });
                
        } catch (const std::exception& e) {
                LOG_ERROR("Exception handling new connection: {}", e.what());
        }
    }

    void connect_to_target(tcp::socket client_socket, const std::string& session_id, 
                          tcp::resolver::results_type results) {
        auto server_socket = std::make_shared<tcp::socket>(io_context_);
        
        asio::async_connect(*server_socket, results,
            [this, session_id, client_socket = std::move(client_socket), server_socket]
            (std::error_code ec, const tcp::endpoint& connected_endpoint) mutable {
                
                if (ec) {
                    LOG_WARN("Failed to connect to target server for session {}: {}", session_id, ec.message());
                    return;
                }
                
                LOG_DEBUG("Connected to target server: {} -> {}:{}", 
                         session_id, connected_endpoint.address().to_string(), connected_endpoint.port());
                
                // Configure server socket
                if (config_.performance.enable_tcp_nodelay) {
                    server_socket->set_option(tcp::no_delay(true));
                }
                if (config_.performance.enable_keep_alive) {
                    server_socket->set_option(asio::socket_base::keep_alive(true));
                }
                
                // Create and start the WebSocket session
                auto session = std::make_shared<WebSocketSession>(
                    std::move(client_socket),
                    io_context_,
                    server_socket,
                    rate_limiter_,
                    buffer_pool_,
                    session_id,
                    config_
                );
                
                session->start();
            });
    }

    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    tcp::resolver resolver_;
    Config config_;
    std::shared_ptr<RateLimiter> rate_limiter_;
    std::shared_ptr<BufferPool> buffer_pool_;
};

// ================= Main Function =================
int main(int argc, char* argv[]) {
    // Initialize logging system first
    init_logging_system();

    try {
        LOG_INFO("WebSocket Proxy starting");
        
        // Load configuration
        std::string config_file = "config.ini";
        if (argc > 1) config_file = argv[1];
        
        auto config = ConfigLoader::load(config_file);

        // Create I/O context and proxy
        asio::io_context io_context;
        WebSocketProxy proxy(io_context, config);

        // Determine thread count
        int thread_count = config.performance.io_threads;
        if (thread_count <= 0) {
            thread_count = static_cast<int>(std::thread::hardware_concurrency());
            if (thread_count == 0) thread_count = 2;
        }

        // Start worker threads
        std::vector<std::thread> worker_threads;
        for (int i = 0; i < thread_count; ++i) {
            worker_threads.emplace_back([&io_context, i] {
                LOG_DEBUG("Worker thread {} starting", i);
                try {
                    io_context.run();
                } catch (const std::exception& e) {
                    LOG_ERROR("Worker thread {} exception: {}", i, e.what());
                }
                LOG_DEBUG("Worker thread {} finished", i);
            });
        }

        // Set up signal handling for graceful shutdown
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&io_context](const std::error_code& ec, int signal_number) {
            if (ec) {
                LOG_WARN("Signal handling error: {}", ec.message());
                return;
            }
            
            LOG_INFO("Received signal {} - initiating graceful shutdown", signal_number);
            io_context.stop();
        });

        LOG_INFO("Proxy started successfully with {} worker threads", thread_count);
        LOG_INFO("Press Ctrl+C to stop the server");

        // Wait for all threads to complete
        for (auto& thread : worker_threads) {
            thread.join();
        }
        
        LOG_INFO("All worker threads have finished - shutdown complete");

    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        shutdown_logging_system();
        return 1;
    }
    
    shutdown_logging_system();
    return 0;
}