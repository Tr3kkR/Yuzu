#pragma once

// TestRouteSink — in-process implementation of HttpRouteSink for unit
// tests. Registered handlers are stored by (method, pattern); dispatch()
// matches an incoming (method, path) against every registration via
// std::regex (mirrors httplib::Server's routing semantics — patterns may
// be plain strings or raw-string regexes like R"(/api/v1/groups/([^/]+))").
//
// Why: tests that previously stood up an httplib::Server on a random port
// + std::thread acceptor crash under TSan with no TSan report (#438).
// This sink lets each route owner's `register_routes(HttpRouteSink&, ...)`
// overload be exercised in-process. Single-threaded, no sockets, nothing
// for TSan's interceptors to fight with.

#include "http_route_sink.hpp"

#include <httplib.h>

#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class TestRouteSink : public yuzu::server::HttpRouteSink {
public:
    void Get(const std::string& p, Handler h) override     { add("GET",     p, std::move(h)); }
    void Post(const std::string& p, Handler h) override    { add("POST",    p, std::move(h)); }
    void Put(const std::string& p, Handler h) override     { add("PUT",     p, std::move(h)); }
    void Delete(const std::string& p, Handler h) override  { add("DELETE",  p, std::move(h)); }
    void Patch(const std::string& p, Handler h) override   { add("PATCH",   p, std::move(h)); }
    void Options(const std::string& p, Handler h) override { add("OPTIONS", p, std::move(h)); }

    /// Dispatch a synthesized request. Returns nullptr when no route matches
    /// (httplib would return 404 in that case; tests that need 404 semantics
    /// should assert nullptr or pre-set res->status = 404 before this call).
    ///
    /// Pre-sets res->status = 200 so handlers that don't touch status look
    /// the same as production (httplib::Server defaults completed handlers
    /// to 200). Handlers that explicitly set 401/204/403/etc. still win.
    std::unique_ptr<httplib::Response> dispatch(const std::string& method,
                                                 const std::string& path,
                                                 const std::string& body = {},
                                                 const std::string& content_type = "application/json") {
        for (auto& route : routes_) {
            if (route.method != method) continue;
            std::smatch m;
            if (!std::regex_match(path, m, route.regex)) continue;

            httplib::Request req;
            req.method = method;
            req.path = path;
            req.body = body;
            if (!content_type.empty())
                req.set_header("Content-Type", content_type);
            // httplib populates `matches` with the regex capture groups so
            // handlers can extract :path-params via req.matches[1] etc.
            // httplib::Match is a typedef for std::match_results — assign
            // the whole result rather than pushing sub_matches one by one.
            req.matches = m;

            auto res = std::make_unique<httplib::Response>();
            res->status = 200;
            route.handler(req, *res);
            return res;
        }
        return nullptr;
    }

    /// Convenience wrappers for common verbs.
    auto Get(const std::string& path)
        { return dispatch("GET", path); }
    auto Post(const std::string& path, const std::string& body,
              const std::string& ct = "application/json")
        { return dispatch("POST", path, body, ct); }
    auto Put(const std::string& path, const std::string& body,
             const std::string& ct = "application/json")
        { return dispatch("PUT", path, body, ct); }
    auto Delete(const std::string& path)
        { return dispatch("DELETE", path); }

    /// Number of registered routes — handy for assertions in fixture setup.
    std::size_t route_count() const { return routes_.size(); }

private:
    struct Route {
        std::string method;
        std::string pattern;
        std::regex regex;
        Handler handler;
    };

    void add(const std::string& method, const std::string& pattern, Handler h) {
        // httplib treats the pattern as a regex if it contains regex
        // metacharacters; otherwise it's an exact path. We compile every
        // pattern as a regex — plain paths still match exactly because they
        // contain no metachars. Patterns the production code writes as raw
        // strings (R"(/api/v1/groups/([a-f0-9]+))") work as-is.
        routes_.push_back({method, pattern, std::regex(pattern), std::move(h)});
    }

    std::vector<Route> routes_;
};

} // namespace yuzu::server::test
