// Fixture: CWE-94 Code Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: electron_ipc_user_controlled_channel
// SOURCE: function_parameter (payload)
// SINK: ipcRenderer.send
// TAINT_HOPS: 1
// NOTES: User-controlled IPC channel name - can invoke arbitrary main process handlers
// REAL_WORLD: microsoft/vscode electron-browser/window.ts IPC patterns
// Simulated Electron IPC
interface IpcRenderer {
    send(channel: string, ...args: any[]): void;
}

declare const ipcRenderer: IpcRenderer;

function handleReply(payload: { replyChannel: string; data: any }): void {
    // VULNERABLE: attacker controls which IPC channel receives the data
    // Could send credentials to a channel that forwards them externally
    ipcRenderer.send(payload.replyChannel, payload.data);
}
