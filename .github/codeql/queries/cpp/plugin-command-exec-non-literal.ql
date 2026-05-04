/**
 * @name Plugin command-execution call with non-literal argument
 * @description Calls to system(), popen(), or exec*() in Yuzu agent-plugin
 *              source files (agents/plugins/<name>/src/*) where the
 *              command-string argument is not a compile-time string literal
 *              or constant-foldable expression.
 *
 *              Plugin actions are invoked via YuzuCommandHandler::execute(),
 *              whose `action` and `params` arguments arrive from a
 *              CommandRequest that originates with the operator over the
 *              gRPC channel. Any path that lets such input reach a
 *              command-execution sink is a command-injection vulnerability.
 *
 *              The 4 CRITICAL command-injection findings in waves 1-4
 *              (CLAUDE.md governance lesson) all matched exactly this
 *              pattern: system()/popen()/exec*() in agents/plugins/*\/src/*
 *              with a variable that traced back to a CommandRequest field.
 *
 *              Remediation: pass the program path as a string literal and
 *              prefer fork()+execve() with an explicit argv array over
 *              system()/popen() shell invocations. If a non-literal
 *              argument is genuinely required, suppress this alert with a
 *              CodeQL annotation and a written justification.
 *
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/yuzu/plugin-command-exec-non-literal
 * @tags security
 *       external/cwe/cwe-078
 *       yuzu-specific
 */

import cpp

class CommandExecCall extends FunctionCall {
  CommandExecCall() {
    this.getTarget().getName() in [
        // POSIX
        "system", "popen",
        "execl", "execlp", "execle", "execv", "execvp", "execvpe",
        // POSIX wide / Windows MSVCRT equivalents
        "_popen", "_wpopen", "_wsystem",
        "_execl", "_execlp", "_execle", "_execv", "_execvp", "_execvpe",
        "_wexecl", "_wexeclp", "_wexecle", "_wexecv", "_wexecvp", "_wexecvpe"
      ]
  }
}

predicate inPluginSource(Element e) {
  e.getFile().getRelativePath().regexpMatch("agents/plugins/[^/]+/src/.*")
}

from CommandExecCall call, Expr arg
where
  inPluginSource(call) and
  arg = call.getArgument(0) and
  not exists(arg.getValue())
select call,
  "Command-execution call in plugin source with non-literal argument $@. " +
  "Plugin params arrive from operator-controlled CommandRequest payloads. " +
  "Pass a string literal, or refactor to fork()+execve() with an allowlisted argv.",
  arg, arg.toString()
