using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using Microsoft.JSInterop;
using Photino.NET;

namespace BoltShell.App.Services;

/// <summary>
/// Window controls for the frameless (chromeless) window: the app draws its own title bar,
/// so moving, resizing, minimising and maximising are driven from JavaScript (wwwroot/js/app.js).
/// On Windows, moving is handed to the OS (like a native title bar: correct across monitors with
/// different scaling, Aero Snap, drag out of maximised) and resizing follows the OS cursor position.
/// Elsewhere both use pointer deltas from the WebView.
/// </summary>
public sealed partial class WindowService
{
    private PhotinoWindow? _window;
    private (Point Cursor, Point Location, Size Size, string Edge)? _resize;

    /// <summary>True when the app draws its own title bar and window buttons.</summary>
    public bool Frameless { get; private set; }

    public bool IsMaximized { get; private set; }

    /// <summary>macOS shows its window buttons (traffic lights) on the left.</summary>
    public bool IsMac => OperatingSystem.IsMacOS();

    public event Action? Changed;

    public void Attach(PhotinoWindow window, bool frameless)
    {
        _window = window;
        Frameless = frameless;
        // The OS can change the state on its own (Aero Snap, dragging out of maximised, taskbar restore),
        // so every window event re-reads the real state instead of tracking it here.
        window.RegisterMaximizedHandler((_, _) => RefreshState());
        window.RegisterRestoredHandler((_, _) => RefreshState());
        window.RegisterMinimizedHandler((_, _) => RefreshState());
        window.RegisterSizeChangedHandler((_, _) => RefreshState());
    }

    public void Minimize() => _window?.SetMinimized(true);

    public void ToggleMaximize()
    {
        if (_window is null)
            return;
        _window.SetMaximized(!_window.Maximized);
        RefreshState();
    }

    public void Close() => _window?.Close();

    /// <summary>True if the OS performs the drag (Windows); the page then sends no move deltas.</summary>
    [JSInvokable]
    public bool UsesNativeDrag() => OperatingSystem.IsWindows();

    /// <summary>Windows: start the system move loop, exactly as a click on a native title bar would.</summary>
    [JSInvokable]
    public void BeginNativeDrag()
    {
        if (!OperatingSystem.IsWindows() || MainWindowHandle() is not { } hwnd || !GetCursorPos(out var cursor))
            return;
        ReleaseCapture();
        PostMessage(hwnd, WmNcLButtonDown, HtCaption, MakeLParam(cursor.X, cursor.Y));
    }

    /// <summary>Moves the window by a delta in physical pixels (title bar drag; non-Windows).</summary>
    [JSInvokable]
    public void MoveBy(int dx, int dy)
    {
        if (_window is null || _window.Maximized || dx == 0 && dy == 0)
            return;
        // Not Offset(): Photino clamps that to the first monitor's work area, which pins the window to one screen.
        var location = _window.Location;
        _window.SetLocation(new Point(location.X + dx, location.Y + dy));
    }

    /// <summary>Windows: remember cursor and window bounds at the start of an edge/corner resize.</summary>
    [JSInvokable]
    public void BeginResize(string edge)
    {
        if (_window is null || _window.Maximized || !OperatingSystem.IsWindows() || !GetCursorPos(out var cursor))
            return;
        _resize = (new Point(cursor.X, cursor.Y), _window.Location, _window.Size, edge);
    }

    /// <summary>Windows: resize from the start bounds by how far the OS cursor moved (no DPI conversion involved).</summary>
    [JSInvokable]
    public void ResizeToCursor()
    {
        if (_resize is not { } start || _window is null || !GetCursorPos(out var cursor))
            return;
        Apply(start.Edge, start.Location, start.Size, cursor.X - start.Cursor.X, cursor.Y - start.Cursor.Y);
    }

    [JSInvokable]
    public void EndResize() => _resize = null;

    /// <summary>Resizes from an edge or corner ("n", "se", …) by a delta in physical pixels (non-Windows).</summary>
    [JSInvokable]
    public void ResizeBy(string edge, int dx, int dy)
    {
        if (_window is null || IsMaximized)
            return;
        Apply(edge, _window.Location, _window.Size, dx, dy);
    }

    private void Apply(string edge, Point location, Size size, int dx, int dy)
    {
        var min = _window!.MinSize;
        int left = location.X, top = location.Y, width = size.Width, height = size.Height;

        if (edge.Contains('e'))
            width = Math.Max(min.X, width + dx);
        if (edge.Contains('s'))
            height = Math.Max(min.Y, height + dy);
        if (edge.Contains('w'))
        {
            var newWidth = Math.Max(min.X, width - dx);
            left += width - newWidth;
            width = newWidth;
        }
        if (edge.Contains('n'))
        {
            var newHeight = Math.Max(min.Y, height - dy);
            top += height - newHeight;
            height = newHeight;
        }

        var current = _window.Location;
        if (left != current.X || top != current.Y)
            _window.SetLocation(new Point(left, top));
        _window.SetSize(new Size(width, height));
    }

    [JSInvokable]
    public void ToggleMaximizeFromJs() => ToggleMaximize();

    private void RefreshState()
    {
        var maximized = _window?.Maximized == true;
        if (IsMaximized == maximized)
            return;
        IsMaximized = maximized;
        Changed?.Invoke();
    }

    private static IntPtr? MainWindowHandle()
    {
        var handle = Process.GetCurrentProcess().MainWindowHandle;
        return handle == IntPtr.Zero ? null : handle;
    }

    private const uint WmNcLButtonDown = 0x00A1;
    private static readonly IntPtr HtCaption = 2;

    private static IntPtr MakeLParam(int x, int y) => (IntPtr)((y << 16) | (x & 0xFFFF));

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out NativePoint point);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReleaseCapture();

    [LibraryImport("user32.dll", EntryPoint = "PostMessageW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool PostMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
}
