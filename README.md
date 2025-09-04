# WebSocket Cleaner
[Experimental, A more robust client identification mechanism will be added at that time.]
## Why does it exist?
Some DDoS/CC attack protection services on the market, such as Cloudflare,only provide protection during the establishment of WebSocket connections, not after the connection is established (e.g., what messages are actually sent within this WebSocket, or the frequency at which WebSocket frames are sent).
This is a program that parses WebSocket frames and implements rate limiting measures.
It is a lightweight, high-performance gateway program designed to address such issues.

## Features

- **Rate Limiting**: Configurable rate limiting with short-term and long-term windows
- **DDoS Protection**: Automatic banning of abusive clients with configurable ban durations
- **High Performance**: Multi-threaded architecture with buffer pooling and efficient memory management
- **WebSocket Protocol Support**: Full WebSocket protocol compliance including fragmented messages
- **Real-time Monitoring**: Comprehensive logging and statistics tracking
- **Configurable**: Flexible configuration system with runtime reload support
- **Session Management**: Unique session identification and tracking

## Architecture

The WebSocket Cleaner is built with a modern C++20 architecture featuring:

- **Asynchronous I/O**: Based on ASIO for high-performance networking
- **Multi-threaded**: Configurable worker threads for optimal CPU utilization
- **Token Bucket Algorithm**: Efficient rate limiting implementation
- **Buffer Pooling**: Memory-efficient buffer management
- **Sharded Rate Limiting**: Concurrent session management with minimal lock contention

Client/Attacker <===> Cloudflare(WAF, L4/L7 DDoS, TLS,Load-Balancing(but It cannot process messages sent after the WebSocket connection is established.) ) <===> NGINX(TLS terminating, Load-Balancing) <===> ws-cleaner(Websocket Message RateLimiting) <===> Websocket Backend

## Building

### Prerequisites

- CMake 3.15 or higher
- C++20 compatible compiler (GCC 8+, Clang 10+, MSVC 19.28+)

### Build Steps

1. Clone the repository with submodules:
```bash
cd websocket-cleaner
```

2. Create build directory:
```bash
mkdir build && cd build
```

3. Configure and build:
```bash
cmake ..
ninja
```

4. The executable will be created as `ws-cleaner` in the build directory.

## Configuration

The proxy uses a configuration file `config.ini` (defaults provided). Copy `config.ini.example` to `config.ini` and customize as needed:

### Server Configuration
```ini
[server]
listen_address = 0.0.0.0
listen_port = 8082
target_address = localhost
target_port = 8081
```

### Rate Limiting Configuration
```ini
[rate_limit]
max_messages_per_minute = 80
short_window_seconds = 5
short_window_max = 10
long_ban_seconds = 60
short_ban_seconds = 30
ignore_control_frames = false
```

### Performance Configuration
```ini
[performance]
max_websocket_message_size = 16777216  # 16MB limit
enable_tcp_nodelay = true              # Reduce latency
enable_keep_alive = true              # TCP keep-alive
buffer_size = 8192                    # Buffer size for I/O operations
io_threads = 0                        # 0 = auto-detect CPU cores
session_cleanup_interval = 300        # Cleanup interval in seconds
```

## Usage

### Basic Usage

1. Start your WebSocket server on the target port (default: 8081)
2. Start the WebSocket Cleaner:
```bash
./ws-cleaner
```

3. Connect clients to the proxy port (default: 8082) instead of directly to your server

### Custom Configuration File

```bash
./ws-cleaner /path/to/custom/config.ini
```

### Environment Variables

- `WC_LOG`: Set logging level (TRACE, DEBUG, INFO, WARN, ERROR, OFF)
  ```bash
  WC_LOG=DEBUG ./ws-cleaner
  ```

## Rate Limiting Behavior

The proxy implements a dual-window rate limiting system:

### Short Window
- Monitors messages in a short time window (configurable, default: 5 seconds)
- Exceeding the limit results in a short ban (default: 30 seconds)
- Designed to catch rapid bursts of messages

### Long Window
- Monitors messages over a longer period (default: 60 seconds)
- Exceeding the limit results in a longer ban (default: 60 seconds)
- Catches sustained high-rate traffic

### Control Frames
- Ping/pong and close frames can be configured to not count against rate limits
- Helps maintain connection health during legitimate high-traffic scenarios

## Monitoring and Logging

### Log Levels

The proxy provides detailed logging at multiple levels:
- **TRACE**: Detailed frame-by-frame information
- **DEBUG**: Session lifecycle and rate limiting decisions
- **INFO**: Connection events and periodic statistics
- **WARN**: Configuration warnings and non-critical errors
- **ERROR**: Critical errors and failures

### Statistics

The proxy tracks and logs comprehensive statistics every 5 minutes:
- Active sessions
- Total WebSocket messages processed
- Control frames handled
- Dropped messages (rate limited)
- Banned sessions
- Bytes transferred (client-to-server and server-to-client)

### Session Statistics

Individual session statistics can be monitored through the logging system, including:
- Message count per session
- Available tokens in rate limit buckets
- Ban status and remaining time

## Testing

The project includes test clients in the `testfiles/` directory:

### Test Server
```bash
cd testfiles
python3 test_server.py
```
Starts a simple echo WebSocket server on port 8081.

### Normal Speed Client
```bash
cd testfiles
python3 normal_speed_client.py
```
Sends messages at 1-second intervals to test normal operation.

### High Speed Client
```bash
cd testfiles
python3 high_speed_client.py
```
Sends messages rapidly to test rate limiting behavior.

### Attacker Client
```bash
cd testfiles
python3 attacker_client.py
```
Simulates a DDoS attack to test banning mechanisms.

## Security Features

### Session Identification
- Each connection gets a unique, cryptographically random session ID
- Session IDs include timestamp and counter for uniqueness
- Thread-local random number generators for performance

### Ban Mechanisms
- Automatic banning when rate limits are exceeded
- Configurable ban durations for short and long window violations
- Automatic unban after ban period expires
- Session cleanup for inactive connections

### Memory Protection
- Configurable maximum WebSocket message size
- Buffer pooling to prevent memory exhaustion
- Input validation and sanitization

## Performance Considerations

### Thread Configuration
- Default: Auto-detect number of CPU cores
- Can be manually configured based on workload
- Each thread runs its own ASIO event loop

### Memory Management
- Buffer pooling reduces allocation overhead
- Configurable buffer sizes based on expected message sizes
- Automatic cleanup of inactive sessions

### Network Optimization
- TCP_NODELAY enabled by default for low latency
- Optional TCP keep-alive for connection stability
- Efficient socket handling with proper error recovery

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Verify target server is running and accessible
   - Check network configuration and firewall settings

2. **High Memory Usage**
   - Adjust buffer pool size in configuration
   - Review session cleanup interval settings

3. **Performance Issues**
   - Monitor CPU usage and adjust thread count
   - Check for network bottlenecks
   - Review rate limiting settings

4. **Clients Getting Banned**
   - Review rate limiting configuration
   - Check if control frames are being counted
   - Monitor client behavior patterns

### Debug Mode

Enable debug logging for detailed troubleshooting:
```bash
WC_LOG=DEBUG ./ws-cleaner
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the test files for usage examples

## Acknowledgments

- Built with ASIO for high-performance networking
- Uses spdlog for efficient logging
- Implements industry-standard rate limiting algorithms
- Designed with security and performance as primary goals
