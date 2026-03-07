// Legacy procfetch UI — kept as a stub. The unified dashboard (dashboard_ui.cpp)
// is now served at /. The old /procfetch route redirects to /.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kProcfetchIndexHtml = R"HTM(<!DOCTYPE html>
<html><head><meta http-equiv="refresh" content="0;url=/"></head>
<body>Redirecting to <a href="/">dashboard</a>...</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
