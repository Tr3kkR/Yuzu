// Drops the PgTestTemplate template databases at testRunEnded — i.e. while
// libpq's TLS stack is still alive. The Registry static destructor is only a
// backstop: its __cxa_atexit slot is claimed when the first [pg] fixture
// runs, so on Catch2-filtered runs OpenSSL's own atexit cleanup can land
// AFTER it and the exit-time PQconnectdb fails, leaking every
// yuzu_test_tpl_* database onto the shared CI instance (see
// PgTestTemplate::drop_all_built in test_helpers.hpp).
//
// One dedicated TU (not the header): CATCH_REGISTER_LISTENER in a header
// would register one listener per including TU.

#if defined(YUZU_TEST_ENABLE_PG)

#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include "../test_helpers.hpp"

namespace {

class PgTemplateCleanupListener : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunEnded(const Catch::TestRunStats& /*stats*/) override {
        yuzu::test::PgTestTemplate::drop_all_built();
    }
};

} // namespace

CATCH_REGISTER_LISTENER(PgTemplateCleanupListener)

#endif // YUZU_TEST_ENABLE_PG
