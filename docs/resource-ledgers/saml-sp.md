# Resource Ledger — SAML 2.0 SP (`saml_provider.cpp`)

This ledger documents every C resource that `SamlProvider::validate_response` and
the surrounding infrastructure own, and its guaranteed release path.  Reviewers must
verify that every code path (normal return, `std::unexpected` early-return, and
exception) releases exactly the listed resources.

---

## Resources

### `xmlDocPtr` — parsed SAML response document
- **Allocated by:** `xmlReadMemory()` (step 2 in `validate_response`)
- **Released by:** `DocGuard` (`struct DocGuard { xmlDocPtr d; ~DocGuard() { if (d) xmlFreeDoc(d); } }`)
- **Scope:** local to `validate_response`; guard is declared immediately after the
  `if (!doc)` early-return, so the only path on which `doc` is non-null is also
  the path on which `DocGuard` destructs it.
- **All paths covered:** normal return ✓ · early-return via `std::unexpected` ✓ ·
  exception (e.g. from `std::string` append) ✓

### `xmlSecDSigCtxPtr` — XML-DSig verification context
- **Allocated by:** `xmlSecDSigCtxCreate(nullptr)` (step 10)
- **Released by:** `DsigGuard` (`struct DsigGuard { xmlSecDSigCtxPtr c; ~DsigGuard() { ... } }`)
- **Scope:** local to `validate_response`; guard declared immediately after the
  `if (!dsig_ctx)` early-return.
- **Key transfer:** `dsig_ctx->signKey = sign_key` transfers ownership of the
  `xmlSecKeyPtr` into the context; `DsigGuard` calls `xmlSecDSigCtxDestroy(c)` which
  in turn calls `xmlSecKeyDestroy(dsig_ctx->signKey)`.  The key is therefore
  **released exactly once** via the context destructor.
- **All paths covered:** ✓ (same as `DocGuard`)

### `xmlSecKeyPtr` — pinned IdP signing key
- **Allocated by:** `xmlSecOpenSSLAppKeyLoadMemory()` (step 9)
- **Released by:** transferred to `dsig_ctx->signKey`; freed indirectly by
  `DsigGuard → xmlSecDSigCtxDestroy`.
- **Leak window:** between `xmlSecOpenSSLAppKeyLoadMemory` success and
  `xmlSecDSigCtxCreate` success.  The early-return between these two points is
  `if (!dsig_ctx) { xmlSecKeyDestroy(sign_key); return std::unexpected(...); }` —
  an explicit manual free, not a guard, because the key is not yet attached to
  anything.  **This is the only manual-free site**; all other release paths go
  through `DsigGuard`.

### `z_stream` — zlib DEFLATE state (in `deflate_raw`)
- **Allocated by:** `deflateInit2()` in `deflate_raw` (used by `build_authn_request`)
- **Released by:** `deflateEnd(&zs)` in the same function, called unconditionally
  before any throw.  The function is exception-clean: it calls `deflateEnd` before
  the `if (ret != Z_STREAM_END) throw` line.

### `std::ifstream` — IdP cert PEM file (in `server.cpp`)
- **Allocated by:** `std::ifstream cert_file(cfg_.saml_idp_cert)` in `ServerImpl::run()`
- **Released by:** RAII destructor of `std::ifstream` at the end of the enclosing
  `else` block.  No manual close required.

---

## Global / process-lifetime resources (intentionally not released)

### xmlsec1 / libxml2 global state
- **Initialised by:** `do_xmlsec_init()` → `xmlInitParser()`, `xmlSecInit()`,
  `xmlSecOpenSSLAppInit()`, `xmlSecOpenSSLInit()`; guarded by `std::call_once`.
- **Not shut down:** xmlsec recommends `xmlSecShutdown()` / `xmlSecOpenSSLShutdown()` /
  `xmlCleanupParser()` at process exit, but these are **intentionally omitted** because:
  1. `SamlProvider` is a process-lifetime singleton — there is no valid "last user"
     to own the cleanup.
  2. libxml2's cleanup functions are not thread-safe; racing them with in-flight
     requests would introduce use-after-free.
  3. The OS reclaims all memory at process exit anyway.
- **Decision recorded:** code comment in `saml_provider.cpp` at the
  `g_xmlsec_init_flag` site.

---

## Non-owning references

### `saml::SamlProvider*` in `AuthRoutes`
- `AuthRoutes` holds a non-owning raw pointer to `SamlProvider` (set via constructor
  parameter).
- Lifetime: `ServerImpl` owns `saml_provider_` as a `std::unique_ptr<SamlProvider>`
  and constructs `AuthRoutes` with a raw pointer to it.  `ServerImpl::stop()` drains
  in-flight gRPC/HTTP handlers before destroying `saml_provider_`, so the pointer
  is always valid during request handling.
- No ownership transfer, no deletion responsibility in `AuthRoutes`.
