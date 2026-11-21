package com.gkeyes.lhasa26.core;

/** Result of one shell command executed through the Shizuku shell identity. */
public final class CommandResult {
    public final int exitCode;
    public final String output;

    public CommandResult(int exitCode, String output) {
        this.exitCode = exitCode;
        this.output = output == null ? "" : output;
    }

    public boolean isSuccess() {
        return exitCode == 0;
    }
}
