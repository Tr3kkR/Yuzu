/**
 * @name DIAGNOSTIC — every popen/system/exec in agents/plugins source
 * @description Temporary diagnostic — fires on every system/popen/exec
 *              call in agents/plugins/<name>/src/* with no argument
 *              constraint. Lets us triangulate why the production
 *              queries (plugin-command-exec-non-literal,
 *              plugin-windows-process-spawn-non-literal) produced 0
 *              alerts despite many obvious call sites in plugin source.
 *
 *              Compare alert count against the production-query alert
 *              count — if this diagnostic fires N times and the
 *              production query fires 0 times, the bug is either
 *              `arg.getValue()` folding too aggressively or a wrong
 *              argument-position selection. If both fire 0, the bug is
 *              in either the function-name match or the path predicate.
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
  "DIAGNOSTIC: " + call.getTarget().getName() + " call in plugin source"
