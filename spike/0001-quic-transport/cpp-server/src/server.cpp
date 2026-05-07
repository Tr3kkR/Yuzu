// Throwaway msquic echo server for #376 PR 0 spike.
//
// Listens on udp/<port>, ALPN "yuzu-spike". On a single bidirectional stream:
//   - normal mode:       echo every received chunk back to the peer
//   - slow-reader mode:  echo for ~2s, then disable receive for 5s, then resume
//
// Logs go to stderr (per-line millisecond timestamp).
// Frame counts and end-of-run stats go to stdout as a single JSON object,
// for easy ingestion into the evidence file.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include "msquic.h"

namespace {

// CLI knobs.
struct Args {
    uint16_t port = 50053;
    std::string cert_path;
    std::string key_path;
    std::string mode = "normal";  // normal | slow-reader
    int slow_after_ms = 2000;
    int slow_pause_ms = 5000;
};

// API table singleton, set up by MsQuicOpen2 and torn down at shutdown.
const QUIC_API_TABLE* g_msquic = nullptr;
HQUIC g_registration = nullptr;
HQUIC g_configuration = nullptr;
HQUIC g_listener = nullptr;

std::atomic<uint64_t> g_bytes_received{0};
std::atomic<uint64_t> g_bytes_sent{0};
std::atomic<uint64_t> g_chunks_received{0};
std::atomic<uint64_t> g_chunks_sent{0};

// Half-close timing: when did we get PEER_SEND_SHUTDOWN, when did SHUTDOWN_COMPLETE fire.
std::atomic<int64_t> g_peer_send_shutdown_ms{-1};
std::atomic<int64_t> g_stream_shutdown_complete_ms{-1};

// Slow-reader scheduling.
std::atomic<int64_t> g_first_receive_ms{-1};
std::atomic<int64_t> g_slow_reader_disable_ms{-1};
std::atomic<int64_t> g_slow_reader_reenable_ms{-1};

std::atomic<bool> g_done{false};
Args g_args;

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void log_line(const char* tag, const std::string& msg) {
    std::fprintf(stderr, "[%lld ms] [%s] %s\n", static_cast<long long>(now_ms()), tag, msg.c_str());
    std::fflush(stderr);
}

// Heap-allocated buffer for outbound StreamSend; ClientSendContext points to this
// so we can free it on SEND_COMPLETE.
struct EchoBuffer {
    QUIC_BUFFER quic;
    uint8_t* data;
    EchoBuffer(const uint8_t* src, uint32_t len) {
        data = static_cast<uint8_t*>(std::malloc(len));
        std::memcpy(data, src, len);
        quic.Buffer = data;
        quic.Length = len;
    }
    ~EchoBuffer() { std::free(data); }
    EchoBuffer(const EchoBuffer&) = delete;
    EchoBuffer& operator=(const EchoBuffer&) = delete;
};

// Stream callback. Runs on msquic worker thread.
QUIC_STATUS QUIC_API stream_callback(HQUIC stream, void* /*ctx*/, QUIC_STREAM_EVENT* ev) {
    switch (ev->Type) {
        case QUIC_STREAM_EVENT_RECEIVE: {
            uint64_t total = 0;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                const auto& buf = ev->RECEIVE.Buffers[i];
                total += buf.Length;
                auto* echo = new EchoBuffer(buf.Buffer, buf.Length);
                QUIC_STATUS st = g_msquic->StreamSend(
                    stream, &echo->quic, 1, QUIC_SEND_FLAG_NONE, echo);
                if (QUIC_FAILED(st)) {
                    log_line("stream", "StreamSend failed " + std::to_string(st));
                    delete echo;
                } else {
                    g_bytes_sent.fetch_add(buf.Length);
                    g_chunks_sent.fetch_add(1);
                }
            }
            g_bytes_received.fetch_add(total);
            g_chunks_received.fetch_add(ev->RECEIVE.BufferCount);

            if (g_first_receive_ms.load() < 0) {
                g_first_receive_ms.store(now_ms());
                if (g_args.mode == "slow-reader") {
                    // Schedule disable + re-enable on a detached thread so we don't
                    // block the msquic worker.
                    std::thread([stream]() {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(g_args.slow_after_ms));
                        log_line("slow-reader", "disabling receive");
                        g_slow_reader_disable_ms.store(now_ms());
                        g_msquic->StreamReceiveSetEnabled(stream, FALSE);
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(g_args.slow_pause_ms));
                        log_line("slow-reader", "re-enabling receive");
                        g_slow_reader_reenable_ms.store(now_ms());
                        g_msquic->StreamReceiveSetEnabled(stream, TRUE);
                    }).detach();
                }
            }

            if (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                log_line("stream", "RECEIVE with FIN");
            }
            break;
        }

        case QUIC_STREAM_EVENT_SEND_COMPLETE: {
            auto* echo = static_cast<EchoBuffer*>(ev->SEND_COMPLETE.ClientContext);
            delete echo;
            break;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
            g_peer_send_shutdown_ms.store(now_ms());
            log_line("stream", "PEER_SEND_SHUTDOWN");
            // Half-close our send side once we've drained.
            g_msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
            log_line("stream", "PEER_SEND_ABORTED " +
                std::to_string(ev->PEER_SEND_ABORTED.ErrorCode));
            break;
        }

        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE: {
            log_line("stream", std::string("SEND_SHUTDOWN_COMPLETE graceful=") +
                (ev->SEND_SHUTDOWN_COMPLETE.Graceful ? "1" : "0"));
            break;
        }

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            g_stream_shutdown_complete_ms.store(now_ms());
            log_line("stream", "SHUTDOWN_COMPLETE");
            g_msquic->StreamClose(stream);
            g_done.store(true);
            break;
        }

        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API conn_callback(HQUIC conn, void* /*ctx*/, QUIC_CONNECTION_EVENT* ev) {
    switch (ev->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            log_line("conn", "CONNECTED (TLS handshake done)");
            g_msquic->ConnectionSendResumptionTicket(conn,
                QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
            break;
        }
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            log_line("conn", "PEER_STREAM_STARTED");
            g_msquic->SetCallbackHandler(
                ev->PEER_STREAM_STARTED.Stream,
                reinterpret_cast<void*>(stream_callback),
                nullptr);
            break;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            log_line("conn", "SHUTDOWN_INITIATED_BY_TRANSPORT status=" +
                std::to_string(ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            log_line("conn", "SHUTDOWN_INITIATED_BY_PEER err=" +
                std::to_string(ev->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            log_line("conn", "SHUTDOWN_COMPLETE");
            g_msquic->ConnectionClose(conn);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API listener_callback(HQUIC /*listener*/, void* /*ctx*/, QUIC_LISTENER_EVENT* ev) {
    switch (ev->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            log_line("listener", "NEW_CONNECTION");
            g_msquic->SetCallbackHandler(
                ev->NEW_CONNECTION.Connection,
                reinterpret_cast<void*>(conn_callback),
                nullptr);
            return g_msquic->ConnectionSetConfiguration(
                ev->NEW_CONNECTION.Connection, g_configuration);
        }
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

bool parse_args(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", a.c_str());
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--port") g_args.port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--cert") g_args.cert_path = next();
        else if (a == "--key")  g_args.key_path  = next();
        else if (a == "--mode") g_args.mode      = next();
        else if (a == "--slow-after-ms") g_args.slow_after_ms = std::stoi(next());
        else if (a == "--slow-pause-ms") g_args.slow_pause_ms = std::stoi(next());
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return false; }
    }
    if (g_args.cert_path.empty() || g_args.key_path.empty()) {
        std::fprintf(stderr, "--cert and --key are required\n");
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (!parse_args(argc, argv)) return 2;

    // SIGTERM / SIGINT → set g_done so the main loop exits cleanly and the
    // final JSON line is flushed (otherwise run-all.sh's TERM kills the
    // process before stdout is written).
    auto handler = +[](int /*sig*/) { g_done.store(true); };
    std::signal(SIGTERM, handler);
    std::signal(SIGINT, handler);

    QUIC_STATUS st = MsQuicOpen2(&g_msquic);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "MsQuicOpen2 failed %d\n", st); return 1; }

    const QUIC_REGISTRATION_CONFIG reg_config = {
        "yuzu-quic-spike", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    st = g_msquic->RegistrationOpen(&reg_config, &g_registration);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "RegistrationOpen failed %d\n", st); return 1; }

    const QUIC_BUFFER alpn = { 10, reinterpret_cast<uint8_t*>(const_cast<char*>("yuzu-spike")) };

    QUIC_SETTINGS settings = {};
    settings.IdleTimeoutMs = 60000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = 4;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    st = g_msquic->ConfigurationOpen(g_registration, &alpn, 1,
        &settings, sizeof(settings), nullptr, &g_configuration);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "ConfigurationOpen failed %d\n", st); return 1; }

    QUIC_CERTIFICATE_FILE cert_file = { g_args.key_path.c_str(), g_args.cert_path.c_str() };
    QUIC_CREDENTIAL_CONFIG cred = {};
    cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cred.CertificateFile = &cert_file;

    st = g_msquic->ConfigurationLoadCredential(g_configuration, &cred);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "ConfigurationLoadCredential failed 0x%x\n", st); return 1; }

    st = g_msquic->ListenerOpen(g_registration, listener_callback, nullptr, &g_listener);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "ListenerOpen failed %d\n", st); return 1; }

    QUIC_ADDR addr = {};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&addr, g_args.port);

    st = g_msquic->ListenerStart(g_listener, &alpn, 1, &addr);
    if (QUIC_FAILED(st)) { std::fprintf(stderr, "ListenerStart failed 0x%x\n", st); return 1; }

    log_line("main", "listening on udp/" + std::to_string(g_args.port) +
        " mode=" + g_args.mode + " ALPN=yuzu-spike");

    // Wait until the stream is fully shut down (set by stream callback) or 90s timeout.
    int64_t start = now_ms();
    while (!g_done.load() && (now_ms() - start) < 90000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    g_msquic->ListenerStop(g_listener);
    g_msquic->ListenerClose(g_listener);
    g_msquic->ConfigurationClose(g_configuration);
    g_msquic->RegistrationClose(g_registration);
    MsQuicClose(g_msquic);

    int64_t peer_ms = g_peer_send_shutdown_ms.load();
    int64_t shut_ms = g_stream_shutdown_complete_ms.load();
    int64_t halfclose_lag = (peer_ms >= 0 && shut_ms >= 0) ? (shut_ms - peer_ms) : -1;

    int64_t disable_ms = g_slow_reader_disable_ms.load();
    int64_t reenable_ms = g_slow_reader_reenable_ms.load();
    int64_t slow_pause_observed = (disable_ms >= 0 && reenable_ms >= 0)
        ? (reenable_ms - disable_ms) : -1;

    std::printf(
        "{\"role\":\"server\",\"mode\":\"%s\","
        "\"bytes_received\":%llu,\"bytes_sent\":%llu,"
        "\"chunks_received\":%llu,\"chunks_sent\":%llu,"
        "\"peer_send_shutdown_ms\":%lld,\"stream_shutdown_complete_ms\":%lld,"
        "\"halfclose_lag_ms\":%lld,"
        "\"slow_reader_disable_ms\":%lld,\"slow_reader_reenable_ms\":%lld,"
        "\"slow_pause_observed_ms\":%lld,"
        "\"completed\":%s}\n",
        g_args.mode.c_str(),
        (unsigned long long)g_bytes_received.load(),
        (unsigned long long)g_bytes_sent.load(),
        (unsigned long long)g_chunks_received.load(),
        (unsigned long long)g_chunks_sent.load(),
        (long long)peer_ms, (long long)shut_ms, (long long)halfclose_lag,
        (long long)disable_ms, (long long)reenable_ms, (long long)slow_pause_observed,
        g_done.load() ? "true" : "false");
    return g_done.load() ? 0 : 3;
}
