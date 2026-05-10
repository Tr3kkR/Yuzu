/**
 * @name Plugin Windows process-spawn call with non-literal argument
 * @description Calls to CreateProcessA/W, ShellExecuteA/W, ShellExecuteExA/W,
 *              or WinExec in Yuzu agent-plugin source files
 *              (agents/plugins/<name>/src/*) where the application path,
 *              command line, or file argument is not a compile-time string
 *              literal or constant-foldable expression.
 *
 *              The Windows process-spawn API surface is distinct from POSIX
 *              system()/popen()/exec*() — different sink set, different
 *              argument positions — and the standard CodeQL
 *              security-and-quality suite does not flag it as
 *              project-policy violations the way Yuzu requires (every
 *              command-string in plugin code must be a literal).
 *
 *              The threat model is the same as the POSIX query: plugin
 *              params arrive from CommandRequest, which is operator-
 *              controlled. ShellExecute* in particular invokes the Windows
 *              shell-association handler, so a non-literal lpFile is a
 *              full command-injection sink.
 *
 *              Remediation: pass the program path as a string literal,
 *              prefer CreateProcessW with an explicit lpApplicationName
 *              and a separately-built lpCommandLine where every component
 *              is allowlisted, and never pass operator-controlled strings
 *              to ShellExecute*. If genuinely required, suppress this
 *              alert with a written justification.
 *
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/yuzu/plugin-windows-process-spawn-non-literal
 * @tags security
 *       external/cwe/cwe-078
 *       yuzu-specific
 */

import cpp

/**
 * Windows process-spawn functions with the index of the
 * "command/path" argument that must be literal.
 */
class WindowsSpawnCall extends FunctionCall {
  int commandArgIndex;

  WindowsSpawnCall() {
    // CreateProcessA/W: lpApplicationName is arg 0, lpCommandLine is arg 1.
    // Both must be literal-or-null. We check arg 1 (lpCommandLine) because
    // attackers typically smuggle the payload there; arg 0 is checked
    // separately below.
    this.getTarget().getName() = ["CreateProcessA", "CreateProcessW"] and
    commandArgIndex = 1
    or
    this.getTarget().getName() = ["CreateProcessA", "CreateProcessW"] and
    commandArgIndex = 0
    or
    // ShellExecuteA/W: hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd.
    // lpFile (arg 2) is the executable path; lpParameters (arg 3) is appended.
    this.getTarget().getName() = ["ShellExecuteA", "ShellExecuteW"] and
    commandArgIndex = [2, 3]
    or
    // ShellExecuteExA/W takes a single SHELLEXECUTEINFO* — we cannot
    // statically inspect struct field assignments precisely, so we flag
    // the call site itself when it appears in plugin source as a softer
    // signal. Fold this into the general check by using arg 0 (the
    // SHELLEXECUTEINFO*); the precision is "medium" not "high" for these.
    this.getTarget().getName() = ["ShellExecuteExA", "ShellExecuteExW"] and
    commandArgIndex = 0
    or
    // WinExec(lpCmdLine, uCmdShow) — single command-line argument.
    this.getTarget().getName() = "WinExec" and
    commandArgIndex = 0
  }

  int getCommandArgIndex() { result = commandArgIndex }
}

predicate inPluginSource(Element e) {
  e.getFile().getRelativePath().regexpMatch("agents/plugins/[^/]+/src/.*")
}

from WindowsSpawnCall call, Expr arg
where
  inPluginSource(call) and
  arg = call.getArgument(call.getCommandArgIndex()) and
  not exists(arg.getValue()) and
  // Drop NULL pointers (legitimate for CreateProcess lpApplicationName when
  // lpCommandLine carries the full invocation, and equally for lpOperation).
  not arg instanceof Literal
select call,
  "Windows process-spawn call in plugin source with non-literal argument $@. " +
  "Plugin params arrive from operator-controlled CommandRequest payloads. " +
  "Pass a string literal for the program path, build any command line from " +
  "allowlisted components only, and never pass operator-controlled strings to ShellExecute*.",
  arg, arg.toString()
