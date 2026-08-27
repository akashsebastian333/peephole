// Copy to .opencode/plugins/peephole.ts (plural "plugins").
// Blocks a tool call when peephole denies. JSON is piped on stdin, not interpolated into a shell.
export const Peephole = async ({ $ }: { $: any }) => ({
  "tool.execute.before": async (input: { tool?: string }, output: { args?: Record<string, unknown> }) => {
    const ev = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: input.tool,
      tool_input: output.args ?? {},
    });
    const p = await $`peephole hook --exit2`.stdin(ev).nothrow().quiet();
    if (p.exitCode === 2) {
      throw new Error(String(p.stderr || "blocked by peephole").trim());
    }
  },
});
