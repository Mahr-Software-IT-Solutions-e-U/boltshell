// Glue between the Blazor RdpTab component and the IronRDP web component (MIT/Apache-2.0).
// The RDP stream goes through the app's local RDCleanPath proxy (RdpProxy.cs) on 127.0.0.1.
import * as Rdp from "../lib/ironrdp/iron-remote-desktop-rdp.js";
import "../lib/ironrdp/iron-remote-desktop.js";

let initialized;
const sessions = new Map();

function ensureInit() {
    initialized ??= Rdp.init("WARN");
    return initialized;
}

function describeError(e) {
    if (e && typeof e.kind === "function") {
        // Shown only as a fallback; RdpTab translates known kinds itself.
        const kinds = ["General error", "Wrong password", "Logon failure", "Access denied",
            "Proxy error", "Proxy connection failed", "Negotiation failed"];
        const kind = e.kind();
        let detail = "";
        try { detail = e.backtrace().split("\n")[0]; } catch { }
        let rdcleanpath = null;
        try {
            const d = e.rdcleanpathDetails?.();
            if (d) rdcleanpath = { http: d.httpStatusCode ?? null, wsa: d.wsaErrorCode ?? null, tls: d.tlsAlertCode ?? null };
        } catch { }
        return { kind, message: kinds[kind] ?? "Error", detail, rdcleanpath };
    }
    return { kind: -1, message: String(e?.message ?? e), detail: "", rdcleanpath: null };
}

/**
 * Starts a session inside `container`. Callbacks on `dotnet`: OnConnected(width, height), OnEnded(reason), OnFailed(kind, message, detail).
 */
export async function start(id, container, dotnet, cfg) {
    await ensureInit();
    stop(id);
    const element = document.createElement("iron-remote-desktop");
    element.setAttribute("scale", "fit");
    element.setAttribute("flexcenter", "true");
    element.module = Rdp.Backend;
    element.style.width = "100%";
    element.style.height = "100%";

    const state = { element, ui: null };
    sessions.set(id, state);

    element.addEventListener("ready", async event => {
        const ui = event.detail.irgUserInteraction;
        state.ui = ui;
        let builder = ui.configBuilder()
            .withUsername(cfg.username)
            .withPassword(cfg.password ?? "")
            .withDestination(cfg.destination)
            .withProxyAddress(cfg.proxyAddress)
            .withAuthToken(cfg.token)
            .withDesktopSize({ width: cfg.width, height: cfg.height })
            .withExtension(Rdp.displayControl(true));
        if (cfg.domain) builder = builder.withServerDomain(cfg.domain);
        try {
            const info = await ui.connect(builder.build());
            ui.setVisibility(true);
            ui.setEnableClipboard?.(true);
            const size = info.initialDesktopSize;
            await dotnet.invokeMethodAsync("OnConnected", size?.width ?? cfg.width, size?.height ?? cfg.height);
            const end = await info.run();
            await dotnet.invokeMethodAsync("OnEnded", end.reason());
        } catch (e) {
            const err = describeError(e);
            await dotnet.invokeMethodAsync("OnFailed", err.kind, err.message, err.detail,
                err.rdcleanpath?.http ?? 0, err.rdcleanpath?.wsa ?? 0, err.rdcleanpath?.tls ?? 0);
        }
    }, { once: true });

    container.replaceChildren(element);
}

export function resize(id, width, height) {
    const ui = sessions.get(id)?.ui;
    if (ui && width > 200 && height > 200) ui.resize(Math.floor(width), Math.floor(height));
}

export function ctrlAltDel(id) { sessions.get(id)?.ui?.ctrlAltDel(); }

export function focus(id) { sessions.get(id)?.element?.focus(); }

export function stop(id) {
    const state = sessions.get(id);
    if (!state) return;
    try { state.ui?.shutdown(); } catch { }
    state.element.remove();
    sessions.delete(id);
}
