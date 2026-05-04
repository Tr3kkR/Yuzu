/**
 * @name DIAGNOSTIC — every popen/system/exec in agents/plugins source
 * @description Temporary diagnostic — fires on every system/popen/exec
 *              call in agents/plugins/<name>/src/* with no argument
 *              constraint. Lets us triangulate why the production
 *              queries (plugin-command-exec-non-literal,
 *              plugin-windows-process-spawn-non-literal) produced 0
 *              alerts despite many obvious call sites in plugin source.
 *
 *              If this query fires and the production query doesn't,
 *              the bug is in `arg.getValue()` folding or in the
 *              argument-position selection. If neither fires, the bug
 *              is in the path predicate or the function-name match.
 *              Will be removed once the production queries are
 *              demonstrated to work.
 *
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id cpp/yuzu/diagnostic-popen-in-plugins
 * @tags diagnostic
 *       yuzu-specific
 */

import cpp

class CommandExecCall extends FunctionCall {
  CommandExecCall() {
    this.getTarget().getName() in [
        "system", "popen", "_popen", "_wpopen", "_wsystem",
        "execl", "execlp", "execle", "execv", "execvp", "execvpe"
      ]
  }
}

predicate inPluginSource(Element e) {
  e.getFile().getRelativePath().regexpMatch("agents/plugins/[^/]+/src/.*")
}

from CommandExecCall call
where inPluginSource(call)
select call,
  "DIAGNOSTIC: command-exec call in plugin source. Function: " + call.getTarget().getName() +
  ". File: " + call.getFile().getRelativePath() +
  ". Arg0: " + call.getArgument(0).toString() +
  ". Arg0 has constant value: " + (if exists(call.getArgument(0).getValue()) then "YES" else "NO")
