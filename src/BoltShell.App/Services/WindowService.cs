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
/// different scaling, Aero Snap, drag out of maximised) and resizing follows the OS cursor position;
/// the window keeps invisible frame styles so that Windows offers snapping (see <see cref="EnableSnap"/>).
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
        if (frameless && OperatingSystem.IsWindows())
            window.RegisterWindowCreatedHandler((_, _) => EnableSnap(window.WindowHandle));
    }

    // Keeps the replacement window procedure alive for as long as the window exists.
    private WndProcDelegate? _wndProc;
    private IntPtr _originalWndProc;

    /// <summary>
    /// Windows: a chromeless window has no frame styles, so Windows offers no Aero Snap (dragging to an edge), no
    /// Win+Arrow, no snap layouts and no minimise/maximise animation. Adds the frame styles back and hides the frame
    /// again in WM_NCCALCSIZE, so the whole window stays client area.
    /// </summary>
    private void EnableSnap(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero || _wndProc is not null)
            return;
        _wndProc = WndProc;
        _originalWndProc = SetWindowLongPtr(hwnd, GwlpWndProc, Marshal.GetFunctionPointerForDelegate(_wndProc));
        var style = GetWindowLongPtr(hwnd, GwlStyle);
        SetWindowLongPtr(hwnd, GwlStyle, style | WsCaption | WsThickFrame | WsSysMenu | WsMinimizeBox | WsMaximizeBox);
        SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0, SwpFrameChanged | SwpNoMove | SwpNoSize | SwpNoZOrder | SwpNoActivate);
    }

    private IntPtr WndProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == WmNcCalcSize && wParam != IntPtr.Zero)
        {
            // Maximised windows with a frame are larger than the screen; limit the content to the monitor's work area.
            if (IsZoomed(hwnd))
            {
                var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
                if (GetMonitorInfo(MonitorFromWindow(hwnd, MonitorDefaultToNearest), ref info))
                {
                    var parameters = Marshal.PtrToStructure<NcCalcSizeParams>(lParam);
                    parameters.Rect0 = info.Work;
                    Marshal.StructureToPtr(parameters, lParam, false);
                }
            }
            return IntPtr.Zero; // no non-client area: no visible frame or title bar
        }
        return CallWindowProc(_originalWndProc, hwnd, message, wParam, lParam);
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
    private const uint WmNcCalcSize = 0x0083;
    private const int GwlStyle = -16;
    private const int GwlpWndProc = -4;
    private const long WsCaption = 0x00C00000, WsThickFrame = 0x00040000, WsSysMenu = 0x00080000,
        WsMinimizeBox = 0x00020000, WsMaximizeBox = 0x00010000;
    private const uint SwpNoSize = 0x0001, SwpNoMove = 0x0002, SwpNoZOrder = 0x0004, SwpNoActivate = 0x0010, SwpFrameChanged = 0x0020;
    private const uint MonitorDefaultToNearest = 2;

    private delegate IntPtr WndProcDelegate(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NcCalcSizeParams
    {
        public NativeRect Rect0, Rect1, Rect2;
        public IntPtr WindowPos;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }

    [LibraryImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static partial long GetWindowLongPtr(IntPtr hwnd, int index);

    [LibraryImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
    private static partial IntPtr SetWindowLongPtr(IntPtr hwnd, int index, IntPtr value);

    private static void SetWindowLongPtr(IntPtr hwnd, int index, long value) => SetWindowLongPtr(hwnd, index, (IntPtr)value);

    [LibraryImport("user32.dll", EntryPoint = "CallWindowProcW")]
    private static partial IntPtr CallWindowProc(IntPtr previous, IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowPos(IntPtr hwnd, IntPtr insertAfter, int x, int y, int cx, int cy, uint flags);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsZoomed(IntPtr hwnd);

    [LibraryImport("user32.dll")]
    private static partial IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [LibraryImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);
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
