// Keeps each xterm.js terminal sized to its container (window resize, drawer toggle, tab switch).
window.pbssh = {
    fit(terminalId) {
        try {
            const entry = XtermBlazor.getTerminalObjectById(terminalId);
            const el = entry.terminal.element;
            // Hidden tabs have no size; fitting them would shrink the terminal to 1x1.
            if (el && el.offsetParent !== null && el.clientWidth > 0) {
                entry.addons.get("addon-fit").fit();
            }
        } catch {
            // terminal already disposed
        }
    },

    observeFit(element, terminalId) {
        if (!element || element._pbsshObserver) return;
        let pending = 0;
        const observer = new ResizeObserver(() => {
            cancelAnimationFrame(pending);
            pending = requestAnimationFrame(() => window.pbssh.fit(terminalId));
        });
        observer.observe(element);
        element._pbsshObserver = observer;
        window.pbssh.fit(terminalId);
        // xterm measures glyph width when it opens. If the bundled font loads later, the cell width is wrong
        // (uneven letter spacing). Re-assigning the font family forces xterm to re-measure.
        Promise.all(["400 13px 'JetBrains Mono'", "700 13px 'JetBrains Mono'"].map(f => document.fonts?.load(f)))
            .catch(() => {})
            .then(() => {
                try {
                    const term = XtermBlazor.getTerminalObjectById(terminalId).terminal;
                    const family = term.options.fontFamily;
                    term.options.fontFamily = "monospace";
                    term.options.fontFamily = family;
                } catch {
                    // terminal already disposed
                }
                window.pbssh.fit(terminalId);
            });
    },

    unobserve(element) {
        element?._pbsshObserver?.disconnect();
        if (element) element._pbsshObserver = null;
    }
};

// Ctrl+K / Cmd+K focuses the quick-connect field, even while a terminal has focus (capture phase).
document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "k") {
        const input = document.getElementById("quick-connect");
        if (input) {
            e.preventDefault();
            e.stopPropagation();
            input.focus();
            input.select();
        }
    }
}, true);

// Highlights the SFTP drop zone while files are dragged over it.
window.pbsshDropzone = {
    attach(element) {
        if (!element || element._pbsshDrop) return;
        const on = () => element.classList.add("over");
        const off = () => element.classList.remove("over");
        element.addEventListener("dragenter", on);
        element.addEventListener("dragover", on);
        element.addEventListener("dragleave", off);
        element.addEventListener("drop", off);
        element._pbsshDrop = true;
    }
};

// Frameless window: drag the window by any [data-drag] area (title bars), double-click to maximise,
// and resize with the invisible [data-resize] grips.
// Windows: the OS runs the move loop (correct across monitors with different scaling) and resizing follows the
// OS cursor position. Other platforms: pointer deltas converted to physical pixels.
window.pbsshWindow = {
    async init(dotnet) {
        if (this._net) return;
        this._net = dotnet;
        const native = await dotnet.invokeMethodAsync("UsesNativeDrag");
        const interactive = "button, input, select, textarea, a, label, [data-no-drag], [role=tab]";

        // Calls `tick` at most once per animation frame while the pointer is held; `onEnd` when released.
        const follow = (e, tick, onEnd) => {
            const target = e.target;
            try { target.setPointerCapture(e.pointerId); } catch { }
            let frame = 0;
            const move = ev => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; tick(ev); }); };
            const up = () => {
                target.removeEventListener("pointermove", move);
                target.removeEventListener("pointerup", up);
                target.removeEventListener("pointercancel", up);
                if (frame) cancelAnimationFrame(frame);
                onEnd?.();
            };
            target.addEventListener("pointermove", move);
            target.addEventListener("pointerup", up);
            target.addEventListener("pointercancel", up);
            e.preventDefault();
        };

        // Accumulates screen-coordinate deltas (CSS px) and reports them in physical pixels.
        const deltas = (e, report) => {
            let lastX = e.screenX, lastY = e.screenY;
            return ev => {
                const ratio = window.devicePixelRatio || 1;
                const x = Math.round((ev.screenX - lastX) * ratio), y = Math.round((ev.screenY - lastY) * ratio);
                if (!x && !y) return;
                lastX += x / ratio; lastY += y / ratio;
                report(x, y);
            };
        };

        document.addEventListener("pointerdown", e => {
            if (e.button !== 0) return;
            const grip = e.target.closest("[data-resize]");
            if (grip) {
                const edge = grip.dataset.resize;
                if (native) {
                    dotnet.invokeMethodAsync("BeginResize", edge);
                    follow(e, () => dotnet.invokeMethodAsync("ResizeToCursor"), () => dotnet.invokeMethodAsync("EndResize"));
                } else {
                    follow(e, deltas(e, (x, y) => dotnet.invokeMethodAsync("ResizeBy", edge, x, y)));
                }
                return;
            }
            if (e.target.closest("[data-drag]") && !e.target.closest(interactive) && e.detail < 2) {
                if (native) {
                    e.preventDefault();
                    dotnet.invokeMethodAsync("BeginNativeDrag");
                } else {
                    follow(e, deltas(e, (x, y) => dotnet.invokeMethodAsync("MoveBy", x, y)));
                }
            }
        }, true);

        document.addEventListener("dblclick", e => {
            if (e.target.closest("[data-drag]") && !e.target.closest(interactive)) {
                dotnet.invokeMethodAsync("ToggleMaximizeFromJs");
            }
        }, true);
    }
};

// Size of an RDP tab's container in CSS pixels, used as the requested remote desktop size.
window.pbsshRdp = {
    size(element) {
        const r = element?.getBoundingClientRect();
        return [Math.round(r?.width || 1280), Math.round(r?.height || 800)];
    }
};

// Viewport position of a menu button: [right edge, bottom edge] in CSS pixels.
window.pbsshMenu = {
    anchor(element) {
        const r = element.getBoundingClientRect();
        return [r.right, r.bottom];
    }
};

// Language of the static page parts (index.html), set by App.razor whenever the UI language changes.
window.pbsshLanguage = (lang, errorText, reloadText) => {
    document.documentElement.lang = lang;
    const message = document.querySelector("#blazor-error-ui .error-text-message");
    if (message) message.textContent = errorText;
    const reload = document.querySelector("#blazor-error-ui .reload");
    if (reload) reload.textContent = reloadText;
};
