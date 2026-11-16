using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Wpf.Ui.Appearance;

namespace StartupGuard.App;

public partial class App : Application
{
    public const string ActivatePipeName = "StartupGuard_App_Activate_Pipe";
    public static string? InitialNavigationPage { get; private set; }
    public static string? ScreenshotOutputDirectory { get; private set; }
    public static bool IsScreenshotMode => !string.IsNullOrWhiteSpace(ScreenshotOutputDirectory);
    private static Mutex? _singleInstanceMutex;

    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        string? requestedPage = null;
        for (int i = 0; i < e.Args.Length; i++)
        {
            string arg = e.Args[i];
            if (arg.StartsWith("--page=", StringComparison.OrdinalIgnoreCase))
            {
                requestedPage = arg["--page=".Length..].Trim();
            }
            else if (string.Equals(arg, "--screenshot", StringComparison.OrdinalIgnoreCase))
            {
                ScreenshotOutputDirectory = (i + 1 < e.Args.Length && !e.Args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    ? e.Args[++i]
                    : "assets";
            }
            else if (arg.StartsWith("--screenshot=", StringComparison.OrdinalIgnoreCase))
            {
                ScreenshotOutputDirectory = arg["--screenshot=".Length..].Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(ScreenshotOutputDirectory))
                    ScreenshotOutputDirectory = "assets";
            }
        }
        InitialNavigationPage = requestedPage;

        if (!IsScreenshotMode)
        {
            bool createdNew = true;
            try
            {
                _singleInstanceMutex = new Mutex(initiallyOwned: true, "Local\\StartupGuard_App_SingleInstance_Mutex", out createdNew);
            }
            catch
            {
                createdNew = true;
            }

            if (!createdNew)
            {
                try
                {
                    using var client = new NamedPipeClientStream(".", ActivatePipeName, PipeDirection.Out);
                    client.Connect(600);
                    byte[] msg = Encoding.UTF8.GetBytes(requestedPage ?? "ACTIVATE");
                    client.Write(msg, 0, msg.Length);
                    client.Flush();
                }
                catch { }

                Shutdown(0);
                return;
            }
        }

        base.OnStartup(e);
        try
        {
            string themePref = StartupGuard.Core.Configuration.UserSettingsStore.GetThemePreference();
            ApplicationTheme initialTheme = themePref switch
            {
                "Light" => ApplicationTheme.Light,
                "Dark" => ApplicationTheme.Dark,
                _ => StartupGuard.Core.Configuration.UserSettingsStore.IsSystemAppsLightTheme()
                    ? ApplicationTheme.Light
                    : ApplicationTheme.Dark
            };
            ApplicationThemeManager.Apply(initialTheme, Wpf.Ui.Controls.WindowBackdropType.Mica, true);
        }
        catch
        {
            try
            {
                ApplicationThemeManager.Apply(ApplicationTheme.Dark);
            }
            catch { }
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        string fullLogPath = LogCrash("DispatcherUnhandledException", e.Exception);
        string logDir = Path.GetDirectoryName(fullLogPath) ?? string.Empty;

        Exception realEx = e.Exception;
        while (realEx is System.Reflection.TargetInvocationException && realEx.InnerException != null)
        {
            realEx = realEx.InnerException;
        }

        string errorDisplay = $"{realEx.GetType().Name}: {realEx.Message}";
        ShowFallbackCrashWindow(errorDisplay, fullLogPath, logDir);
        e.Handled = true; // 阻止进程直接崩溃被 WER 挂起终止
    }

    private void ShowFallbackCrashWindow(string errorMessage, string logPath, string logDir)
    {
        try
        {
            var win = new Wpf.Ui.Controls.FluentWindow
            {
                Title = "StartupGuard 异常提示",
                Width = 440,
                MinWidth = 0,
                MinHeight = 0,
                SizeToContent = SizeToContent.Height,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                ResizeMode = ResizeMode.NoResize,
                ExtendsContentIntoTitleBar = true,
                WindowBackdropType = Wpf.Ui.Controls.WindowBackdropType.Mica,
                UseLayoutRounding = true,
                SnapsToDevicePixels = true
            };
            win.SourceInitialized += (_, _) => StartupGuard.Themes.FluentBackdropHelper.ApplyMica(
                win, !StartupGuard.Core.Configuration.UserSettingsStore.IsSystemAppsLightTheme());
            TextOptions.SetTextFormattingMode(win, TextFormattingMode.Display);
            TextOptions.SetTextRenderingMode(win, TextRenderingMode.ClearType);
            RenderOptions.SetClearTypeHint(win, ClearTypeHint.Enabled);

            var rootGrid = new Grid();
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var titleBar = new Wpf.Ui.Controls.TitleBar
            {
                Title = "StartupGuard",
                ShowMaximize = false,
                ShowMinimize = false
            };
            Grid.SetRow(titleBar, 0);
            rootGrid.Children.Add(titleBar);

            var mainPanel = new StackPanel
            {
                Margin = new Thickness(16, 4, 16, 14)
            };
            Grid.SetRow(mainPanel, 1);
            rootGrid.Children.Add(mainPanel);

            mainPanel.Children.Add(new TextBlock
            {
                Text = "程序运行出现异常",
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 6),
                TextAlignment = TextAlignment.Left
            });

            mainPanel.Children.Add(new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x18, 0xD1, 0x34, 0x38)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0xD1, 0x34, 0x38)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 6, 10, 6),
                Margin = new Thickness(0, 0, 0, 8),
                Child = new TextBlock
                {
                    Text = errorMessage,
                    FontSize = 13,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38)),
                    TextWrapping = TextWrapping.Wrap,
                    TextAlignment = TextAlignment.Left
                }
            });

            mainPanel.Children.Add(new TextBlock
            {
                Text = "日志文件:",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 4),
                TextAlignment = TextAlignment.Left
            });

            mainPanel.Children.Add(new Wpf.Ui.Controls.TextBox
            {
                Text = logPath,
                IsReadOnly = true,
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 12)
            });

            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var btnOpen = new Wpf.Ui.Controls.Button
            {
                Content = "打开日志文件夹",
                Padding = new Thickness(14, 6, 14, 6),
                Margin = new Thickness(0, 0, 10, 0),
                Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary
            };
            btnOpen.Click += (_, _) => OpenLogFolder(logPath, logDir);

            var btnOk = new Wpf.Ui.Controls.Button
            {
                Content = "确定",
                IsDefault = true,
                Padding = new Thickness(20, 6, 20, 6),
                Appearance = Wpf.Ui.Controls.ControlAppearance.Primary
            };
            btnOk.Click += (_, _) => win.Close();

            btnPanel.Children.Add(btnOpen);
            btnPanel.Children.Add(btnOk);
            mainPanel.Children.Add(btnPanel);

            win.Content = rootGrid;
            win.ShowDialog();
        }
        catch { }
    }

    private static void OpenLogFolder(string logPath, string logDir)
    {
        try
        {
            string safeCwd = Directory.Exists(logDir) ? logDir : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (File.Exists(logPath))
            {
                using var proc = Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{logPath}\"")
                {
                    WorkingDirectory = safeCwd,
                    UseShellExecute = true
                });
            }
            else if (Directory.Exists(logDir))
            {
                using var proc = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{logDir}\"")
                {
                    WorkingDirectory = safeCwd,
                    UseShellExecute = true
                });
            }
        }
        catch { }
    }

    private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        LogCrash("CurrentDomainUnhandledException", e.ExceptionObject as Exception);
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        LogCrash("UnobservedTaskException", e.Exception);
        e.SetObserved();
    }

    public static string LogCrash(string context, Exception? ex)
    {
        string logDir;
        try
        {
            logDir = StartupGuard.Core.Storage.SharedStorageHelper.GetSharedLogsDirectory();
        }
        catch
        {
            logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "logs");
        }
        string logPath = Path.Combine(logDir, "crash.log");

        if (ex is null) return logPath;
        try
        {
            Directory.CreateDirectory(logDir);
            string entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{context}] {ex}\n";
            File.AppendAllText(logPath, entry);
        }
        catch { }
        return logPath;
    }
}
