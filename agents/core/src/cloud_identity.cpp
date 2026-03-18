#include <yuzu/agent/cloud_identity.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::agent {

namespace {

// IMDS addresses
constexpr const char* kImdsIp = "169.254.169.254";
constexpr int kImdsPort = 80;
constexpr int kTimeoutMs = 2000; // 2 second timeout per provider

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;

void close_socket(socket_t s) {
    closesocket(s);
}

struct WsaInit {
    WsaInit() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WsaInit() { WSACleanup(); }
};

void ensure_wsa() {
    static WsaInit init;
    (void)init;
}

#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;

void close_socket(socket_t s) {
    close(s);
}
void ensure_wsa() {}
#endif

/// Connect to host:port with a timeout. Returns socket or kInvalidSocket.
socket_t connect_with_timeout(const char* host, int port, int timeout_ms) {
    ensure_wsa();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    std::snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        return kInvalidSocket;
    }

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(res);
        return kInvalidSocket;
    }

    // Set non-blocking for connect timeout
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(sock, FIONBIO, &nb);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int rc = connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

#ifdef _WIN32
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        close_socket(sock);
        return kInvalidSocket;
    }
#else
    if (rc < 0 && errno != EINPROGRESS) {
        close_socket(sock);
        return kInvalidSocket;
    }
#endif

    if (rc != 0) {
        // Wait for connect to complete
#ifdef _WIN32
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) {
            close_socket(sock);
            return kInvalidSocket;
        }
#else
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, timeout_ms) <= 0) {
            close_socket(sock);
            return kInvalidSocket;
        }
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            close_socket(sock);
            return kInvalidSocket;
        }
#endif
    }

    // Set back to blocking with recv timeout
#ifdef _WIN32
    u_long bl = 0;
    ioctlsocket(sock, FIONBIO, &bl);
    DWORD tv_recv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_recv),
               sizeof(tv_recv));
#else
    fcntl(sock, F_SETFL, flags); // restore blocking
    struct timeval tv_recv;
    tv_recv.tv_sec = timeout_ms / 1000;
    tv_recv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_recv, sizeof(tv_recv));
#endif

    return sock;
}

/// Send an HTTP request and read the response body. Returns empty on failure.
std::string http_request(const char* host, int port, const std::string& request, int timeout_ms) {
    auto sock = connect_with_timeout(host, port, timeout_ms);
    if (sock == kInvalidSocket)
        return {};

    // Send request
    auto sent = send(sock, request.data(), static_cast<int>(request.size()), 0);
    if (sent <= 0) {
        close_socket(sock);
        return {};
    }

    // Read response (IMDS responses are small, 8KB buffer is sufficient)
    std::string response;
    char buf[8192];
    int n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
    close_socket(sock);

    // Extract body (after \r\n\r\n)
    auto body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos)
        return {};

    // Check HTTP status
    if (response.size() >= 12 && response.substr(9, 3) != "200") {
        return {};
    }

    return response.substr(body_start + 4);
}

// ── AWS IMDSv2 ──────────────────────────────────────────────────────────────

CloudIdentity try_aws() {
    spdlog::debug("Cloud identity: probing AWS IMDSv2...");

    // Step 1: Get IMDSv2 session token (PUT with TTL)
    std::string token_req = "PUT /latest/api/token HTTP/1.1\r\n"
                            "Host: 169.254.169.254\r\n"
                            "X-aws-ec2-metadata-token-ttl-seconds: 60\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n\r\n";

    auto token = http_request(kImdsIp, kImdsPort, token_req, kTimeoutMs);
    if (token.empty())
        return {};

    // Step 2: Get instance identity document (PKCS7 signed)
    std::string doc_req = "GET /latest/dynamic/instance-identity/pkcs7 HTTP/1.1\r\n"
                          "Host: 169.254.169.254\r\n"
                          "X-aws-ec2-metadata-token: " +
                          token +
                          "\r\n"
                          "Connection: close\r\n\r\n";

    auto pkcs7 = http_request(kImdsIp, kImdsPort, doc_req, kTimeoutMs);
    if (pkcs7.empty())
        return {};

    // Step 3: Get instance ID
    std::string id_req = "GET /latest/meta-data/instance-id HTTP/1.1\r\n"
                         "Host: 169.254.169.254\r\n"
                         "X-aws-ec2-metadata-token: " +
                         token +
                         "\r\n"
                         "Connection: close\r\n\r\n";

    auto instance_id = http_request(kImdsIp, kImdsPort, id_req, kTimeoutMs);

    // Step 4: Get region
    std::string region_req = "GET /latest/meta-data/placement/region HTTP/1.1\r\n"
                             "Host: 169.254.169.254\r\n"
                             "X-aws-ec2-metadata-token: " +
                             token +
                             "\r\n"
                             "Connection: close\r\n\r\n";

    auto region = http_request(kImdsIp, kImdsPort, region_req, kTimeoutMs);

    CloudIdentity id;
    id.provider = "aws";
    id.instance_id = std::move(instance_id);
    id.region = std::move(region);
    id.identity_document.assign(pkcs7.begin(), pkcs7.end());

    spdlog::info("Cloud identity: detected AWS (instance={}, region={})", id.instance_id,
                 id.region);
    return id;
}

// ── Azure IMDS ──────────────────────────────────────────────────────────────

CloudIdentity try_azure() {
    spdlog::debug("Cloud identity: probing Azure IMDS...");

    // Get attested document (signed by Azure)
    std::string doc_req = "GET /metadata/attested/document?api-version=2021-02-01 HTTP/1.1\r\n"
                          "Host: 169.254.169.254\r\n"
                          "Metadata: true\r\n"
                          "Connection: close\r\n\r\n";

    auto doc = http_request(kImdsIp, kImdsPort, doc_req, kTimeoutMs);
    if (doc.empty())
        return {};

    // Get instance metadata for ID/region
    std::string meta_req = "GET /metadata/instance/compute?api-version=2021-02-01 HTTP/1.1\r\n"
                           "Host: 169.254.169.254\r\n"
                           "Metadata: true\r\n"
                           "Connection: close\r\n\r\n";

    auto meta = http_request(kImdsIp, kImdsPort, meta_req, kTimeoutMs);

    // Parse vmId and location from JSON (simple extraction, no JSON lib)
    std::string instance_id, region;
    if (!meta.empty()) {
        auto extract = [&](const std::string& json, const std::string& key) -> std::string {
            auto pos = json.find("\"" + key + "\"");
            if (pos == std::string::npos)
                return {};
            pos = json.find(':', pos);
            if (pos == std::string::npos)
                return {};
            pos = json.find('"', pos);
            if (pos == std::string::npos)
                return {};
            auto end = json.find('"', pos + 1);
            if (end == std::string::npos)
                return {};
            return json.substr(pos + 1, end - pos - 1);
        };
        instance_id = extract(meta, "vmId");
        region = extract(meta, "location");
    }

    CloudIdentity id;
    id.provider = "azure";
    id.instance_id = std::move(instance_id);
    id.region = std::move(region);
    id.identity_document.assign(doc.begin(), doc.end());

    spdlog::info("Cloud identity: detected Azure (vmId={}, location={})", id.instance_id,
                 id.region);
    return id;
}

// ── GCP Metadata ────────────────────────────────────────────────────────────

CloudIdentity try_gcp() {
    spdlog::debug("Cloud identity: probing GCP metadata server...");

    // GCP uses metadata.google.internal (169.254.169.254) with Metadata-Flavor header
    // Get signed identity token (JWT)
    std::string token_req = "GET /computeMetadata/v1/instance/service-accounts/default/identity?"
                            "audience=yuzu-server&format=full HTTP/1.1\r\n"
                            "Host: metadata.google.internal\r\n"
                            "Metadata-Flavor: Google\r\n"
                            "Connection: close\r\n\r\n";

    auto jwt = http_request(kImdsIp, kImdsPort, token_req, kTimeoutMs);
    if (jwt.empty())
        return {};

    // Get instance ID
    std::string id_req = "GET /computeMetadata/v1/instance/id HTTP/1.1\r\n"
                         "Host: metadata.google.internal\r\n"
                         "Metadata-Flavor: Google\r\n"
                         "Connection: close\r\n\r\n";

    auto instance_id = http_request(kImdsIp, kImdsPort, id_req, kTimeoutMs);

    // Get zone (projects/PROJECT_NUM/zones/ZONE)
    std::string zone_req = "GET /computeMetadata/v1/instance/zone HTTP/1.1\r\n"
                           "Host: metadata.google.internal\r\n"
                           "Metadata-Flavor: Google\r\n"
                           "Connection: close\r\n\r\n";

    auto zone = http_request(kImdsIp, kImdsPort, zone_req, kTimeoutMs);
    // Extract region from zone path (e.g. "projects/123/zones/us-central1-a" → "us-central1")
    std::string region;
    if (!zone.empty()) {
        auto last_slash = zone.rfind('/');
        auto zone_name = (last_slash != std::string::npos) ? zone.substr(last_slash + 1) : zone;
        auto last_dash = zone_name.rfind('-');
        if (last_dash != std::string::npos) {
            region = zone_name.substr(0, last_dash);
        }
    }

    CloudIdentity id;
    id.provider = "gcp";
    id.instance_id = std::move(instance_id);
    id.region = std::move(region);
    id.identity_document.assign(jwt.begin(), jwt.end());

    spdlog::info("Cloud identity: detected GCP (instance={}, region={})", id.instance_id,
                 id.region);
    return id;
}

} // anonymous namespace

CloudIdentity detect_cloud_identity() {
    // Try each provider in sequence with short timeouts.
    // On bare-metal / on-prem, all probes fail fast (connect timeout to 169.254.169.254).

    if (auto aws = try_aws(); aws.valid())
        return aws;
    if (auto azure = try_azure(); azure.valid())
        return azure;
    if (auto gcp = try_gcp(); gcp.valid())
        return gcp;

    spdlog::debug("Cloud identity: no cloud provider detected (not running on AWS/Azure/GCP)");
    return {};
}

} // namespace yuzu::agent
