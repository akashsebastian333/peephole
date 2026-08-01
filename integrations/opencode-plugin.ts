// .opencode/plugin/peephole.ts  — hard-blocks a tool call peephole denies.
export const Peephole = async ({ $ }: any) => ({
  "tool.execute.before": async (input: any, output: any) => {
    const ev = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: input.tool, tool_input: output.args });
    const p = await $`echo ${ev} | peephole hook --exit2`.quiet().nothrow();
    if (p.exitCode === 2) throw new Error(p.stderr.toString() || "blocked by peephole");
  },
});
