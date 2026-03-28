using System;
using System.IO;
using System.Text;
using System.Threading;

namespace ACMECertManager
{
    /// <summary>
    /// Manages persistent logging with file rotation based on size limits.
    /// </summary>
    internal sealed class LogManager : IDisposable
    {
        private readonly string _logsDirectory;
        private readonly string _logFilePath;
        private readonly int _maxLogFileSizeBytes;
        private readonly object _lockObject = new();
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the LogManager.
        /// </summary>
        /// <param name="logsDirectory">Directory where log files are stored</param>
        /// <param name="maxLogFileSizeMb">Maximum size of a log file in megabytes before rotation</param>
        public LogManager(string logsDirectory, int maxLogFileSizeMb = 10)
        {
            if (string.IsNullOrWhiteSpace(logsDirectory))
                throw new ArgumentException("Logs directory cannot be null or empty.", nameof(logsDirectory));

            if (maxLogFileSizeMb <= 0)
                throw new ArgumentException("Max log file size must be greater than 0.", nameof(maxLogFileSizeMb));

            _logsDirectory = logsDirectory;
            _logFilePath = Path.Combine(logsDirectory, "acm.log");
            _maxLogFileSizeBytes = maxLogFileSizeMb * 1024 * 1024;

            EnsureLogsDirectory();
        }

        /// <summary>
        /// Writes a message to the log file with rotation if needed.
        /// </summary>
        public void WriteLog(string message)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LogManager));

            if (string.IsNullOrEmpty(message))
                return;

            lock (_lockObject)
            {
                try
                {
                    RotateLogIfNeeded();

                    var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var formattedMessage = $"[{timestamp}] {message}";

                    File.AppendAllText(_logFilePath, formattedMessage + Environment.NewLine);
                }
                catch
                {
                    // Silently fail if logging fails - don't interrupt app flow
                }
            }
        }

        /// <summary>
        /// Gets the current log file size in bytes.
        /// </summary>
        public long GetCurrentLogFileSizeBytes()
        {
            lock (_lockObject)
            {
                try
                {
                    if (File.Exists(_logFilePath))
                    {
                        var fileInfo = new FileInfo(_logFilePath);
                        return fileInfo.Length;
                    }
                }
                catch
                {
                    // Return 0 if we can't determine size
                }

                return 0;
            }
        }

        /// <summary>
        /// Gets all log files in the logs directory, ordered by most recent first.
        /// </summary>
        public string[] GetAllLogFiles()
        {
            lock (_lockObject)
            {
                try
                {
                    if (!Directory.Exists(_logsDirectory))
                        return Array.Empty<string>();

                    var files = Directory.GetFiles(_logsDirectory, "*.log");
                    Array.Sort(files, (a, b) => File.GetLastWriteTime(b).CompareTo(File.GetLastWriteTime(a)));
                    return files;
                }
                catch
                {
                    return Array.Empty<string>();
                }
            }
        }

        /// <summary>
        /// Exports logs to a specified file path.
        /// </summary>
        public void ExportLogs(string exportPath)
        {
            if (string.IsNullOrWhiteSpace(exportPath))
                throw new ArgumentException("Export path cannot be null or empty.", nameof(exportPath));

            lock (_lockObject)
            {
                try
                {
                    var logFiles = GetAllLogFiles();

                    if (logFiles.Length == 0)
                        throw new InvalidOperationException("No log files found to export.");

                    using var writer = new StreamWriter(exportPath, false, Encoding.UTF8);
                    
                    writer.WriteLine("=== ACME Certificate Manager - Log Export ===");
                    writer.WriteLine($"Exported: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine($"Total log files: {logFiles.Length}");
                    writer.WriteLine(new string('=', 50));
                    writer.WriteLine();

                    foreach (var logFile in logFiles)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(logFile);
                            writer.WriteLine($"--- File: {fileInfo.Name} (Created: {fileInfo.CreationTime:yyyy-MM-dd HH:mm:ss}) ---");

                            using var reader = new StreamReader(logFile, Encoding.UTF8);
                            writer.Write(reader.ReadToEnd());
                            writer.WriteLine();
                        }
                        catch
                        {
                            writer.WriteLine($"[ERROR] Could not read {logFile}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"Failed to export logs: {ex.Message}", ex);
                }
            }
        }

        /// <summary>
        /// Clears all log files.
        /// </summary>
        public void ClearLogs()
        {
            lock (_lockObject)
            {
                try
                {
                    var logFiles = GetAllLogFiles();
                    foreach (var logFile in logFiles)
                    {
                        try
                        {
                            File.Delete(logFile);
                        }
                        catch
                        {
                            // Skip files that can't be deleted
                        }
                    }
                }
                catch
                {
                    // Silently fail
                }
            }
        }

        /// <summary>
        /// Gets summary statistics about the logs.
        /// </summary>
        public (int FileCount, long TotalSizeBytes) GetLogStatistics()
        {
            lock (_lockObject)
            {
                try
                {
                    var logFiles = GetAllLogFiles();
                    long totalSize = 0;

                    foreach (var logFile in logFiles)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(logFile);
                            totalSize += fileInfo.Length;
                        }
                        catch
                        {
                            // Skip files that can't be accessed
                        }
                    }

                    return (logFiles.Length, totalSize);
                }
                catch
                {
                    return (0, 0);
                }
            }
        }

        private void RotateLogIfNeeded()
        {
            try
            {
                if (!File.Exists(_logFilePath))
                    return;

                var fileInfo = new FileInfo(_logFilePath);
                if (fileInfo.Length < _maxLogFileSizeBytes)
                    return;

                // Generate archive filename with timestamp
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var archivePath = Path.Combine(_logsDirectory, $"acm_{timestamp}.log");

                // Rename current log to archive
                if (File.Exists(archivePath))
                {
                    // If archive already exists, append to its name
                    var counter = 1;
                    var basePath = Path.Combine(_logsDirectory, $"acm_{timestamp}_");
                    while (File.Exists($"{basePath}{counter}.log"))
                        counter++;
                    archivePath = $"{basePath}{counter}.log";
                }

                File.Move(_logFilePath, archivePath, overwrite: false);

                // Cleanup old archives if needed (keep last 10 archives)
                CleanupOldLogs();
            }
            catch
            {
                // Silently fail if rotation fails
            }
        }

        private void CleanupOldLogs()
        {
            try
            {
                var logFiles = GetAllLogFiles();
                const int maxKeepCount = 10; // Keep current + 9 archives

                if (logFiles.Length > maxKeepCount)
                {
                    // Delete oldest files
                    for (int i = maxKeepCount; i < logFiles.Length; i++)
                    {
                        try
                        {
                            File.Delete(logFiles[i]);
                        }
                        catch
                        {
                            // Skip files that can't be deleted
                        }
                    }
                }
            }
            catch
            {
                // Silently fail
            }
        }

        private void EnsureLogsDirectory()
        {
            try
            {
                Directory.CreateDirectory(_logsDirectory);
            }
            catch
            {
                // Directory might already exist or be inaccessible, but we'll try to write anyway
            }
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
