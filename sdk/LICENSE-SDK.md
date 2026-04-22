# Yuzu Plugin SDK — License and Linking Exception

> **Status: DRAFT — pending legal review.** The wording below must be
> reviewed by counsel before the first AGPL-era release ships. A poorly
> drafted linking exception can either (a) fail to protect proprietary
> plugin authors, or (b) inadvertently exempt the Yuzu agent itself from
> copyleft. Neither outcome is acceptable.

## Overview

The Yuzu agent and server are licensed under the GNU Affero General
Public License, version 3 or any later version (AGPL-3.0-or-later).
Read literally, the AGPL propagates to any code that is combined with
Yuzu — including shared-library plugins that the agent loads at runtime
via `dlopen(3)` / `LoadLibrary`.

This behaviour would make it effectively impossible to ship proprietary
plugins, which is not the intent of the Yuzu project. The Yuzu plugin
mechanism is deliberately designed as a **stable, narrow, C-linkage ABI
boundary** — see [`include/yuzu/plugin.h`](include/yuzu/plugin.h). That
boundary serves the same architectural purpose as, for example, the
boundary between GCC's runtime support library and the user code that
links against it.

Consequently, the copyright holder grants the following **additional
permission** to the AGPL license covering the Yuzu agent and associated
libraries, by analogy to the
[GCC Runtime Library Exception](https://www.gnu.org/licenses/gcc-exception-3.1.html)
and the
[GNU Classpath Exception](https://www.gnu.org/software/classpath/license.html).

## Additional permission under AGPL section 7

As an additional permission under section 7 of the GNU Affero General
Public License, version 3, the copyright holder of the Yuzu Plugin SDK
("SDK") gives permission to propagate a work that consists of an
Independent Plugin combined with the SDK.

For the purposes of this exception:

- **"SDK"** means the stable plugin interface defined by the header
  files contained in the `sdk/include/` directory of the Yuzu source
  distribution and the accompanying documentation, together with any
  compiled artefacts derived solely from those header files.

- **"Yuzu Implementation"** means the agent, server, gateway, plugins
  distributed in `agents/plugins/`, and any other work of authorship
  distributed as part of the Yuzu project that is not part of the SDK
  as defined above. The Yuzu Implementation is licensed under
  AGPL-3.0-or-later without the additional permission granted by this
  document.

- **"Independent Plugin"** means a shared library (`.so`, `.dylib`,
  `.dll`) that:
  1. Interacts with the Yuzu agent **solely** through the SDK — that is,
     it invokes or is invoked via the functions, types, and macros
     declared in `sdk/include/yuzu/plugin.h` and the thin C++ wrapper
     `sdk/include/yuzu/plugin.hpp`.
  2. Does **not** statically link against, copy, or embed any portion of
     the source code of the Yuzu Implementation.
  3. Does **not** depend on any non-ABI-stable internal symbol of the
     Yuzu Implementation.
  4. Is not itself a Derivative Work, under copyright law, of the Yuzu
     Implementation.

- **"Combining"** means loading the Independent Plugin into the address
  space of the Yuzu Implementation at runtime via `dlopen`, `LoadLibrary`,
  or an equivalent dynamic-linking facility, and invoking it through the
  SDK.

The author of an Independent Plugin may license that Independent Plugin
under any license of the author's choosing, including proprietary
licenses, and is not required to make the source code of the
Independent Plugin available under the AGPL. Combining and distributing
the Independent Plugin together with the Yuzu Implementation, in a
single distribution medium or through separate channels, does not cause
the AGPL to apply to the Independent Plugin.

The exception **does not** permit any of the following:

1. Modifying the Yuzu Implementation and failing to distribute the
   modified source under the terms of the AGPL.
2. Re-licensing the SDK headers themselves under terms incompatible
   with the AGPL.
3. Creating a "shim" library that exposes the Yuzu Implementation's
   internal APIs through a thin adapter in order to evade the AGPL
   coverage of the Yuzu Implementation. Such a shim is a Derivative
   Work of the Yuzu Implementation and is therefore governed by the
   AGPL.

If you have questions about whether a particular plugin architecture
qualifies under this exception, contact the copyright holder listed in
the top-level `NOTICE` file.

## License of the SDK itself

The SDK header files in `sdk/include/` are licensed under
AGPL-3.0-or-later, with the additional permission granted above. In
practical terms this means you may copy, modify, and redistribute the
SDK headers under the AGPL, but the exception travels with them so that
plugins compiled against them are not automatically forced to be AGPL
themselves, provided they meet the "Independent Plugin" definition.

## Precedents and further reading

- [GCC Runtime Library Exception v3.1](https://www.gnu.org/licenses/gcc-exception-3.1.html) — permits proprietary software to link against libgcc and libstdc++ without becoming GPL.
- [GNU Classpath Exception](https://www.gnu.org/software/classpath/license.html) — permits proprietary Java applications to link against GPL-licensed standard-library code.
- [FSF FAQ on plugin licensing](https://www.gnu.org/licenses/gpl-faq.html#GPLAndPlugins) — FSF's view on when plugins are combined works.

This exception is based on the structure of those documents and is
intended to produce analogous legal effect for the Yuzu plugin boundary.
