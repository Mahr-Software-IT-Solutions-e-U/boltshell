using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;

namespace BoltShell.App.Services;

/// <summary>
/// Minimal daily log file (app-yyyyMMdd.log) in the config directory; keeps 7 days.
/// Only diagnostics are logged – never passwords or keys.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly BlockingCollection<string> _queue = new(boundedCapacity: 10_000);
    private readonly Thread _writer;

    public FileLoggerProvider(string directory)
    {
        Directory = directory;
        System.IO.Directory.CreateDirectory(directory);
        foreach (var old in new DirectoryInfo(directory).GetFiles("app-*.log").Where(f => f.LastWriteTimeUtc < DateTime.UtcNow.AddDays(-7)))
            old.Delete();
        _writer = new Thread(WriteLoop) { IsBackground = true, Name = "FileLogger" };
        _writer.Start();
    }

    public string Directory { get; }
    public string CurrentFile => Path.Combine(Directory, $"app-{DateTime.Now:yyyyMMdd}.log");

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    private void Enqueue(string line) => _queue.TryAdd(line);

    private void WriteLoop()
    {
        foreach (var line in _queue.GetConsumingEnumerable())
        {
            try
            {
                File.AppendAllText(CurrentFile, line, Encoding.UTF8);
            }
            catch (IOException)
            {
                // log file locked or disk full: drop the line rather than crash the app
            }
        }
    }

    public void Dispose()
    {
        _queue.CompleteAdding();
        _writer.Join(TimeSpan.FromSeconds(2));
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
                return;
            var line = new StringBuilder()
                .Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff")).Append(' ')
                .Append(logLevel.ToString()[..4].ToUpperInvariant()).Append(' ')
                .Append(category).Append(": ")
                .Append(formatter(state, exception));
            if (exception is not null)
                line.AppendLine().Append(exception);
            provider.Enqueue(line.AppendLine().ToString());
        }
    }
}
