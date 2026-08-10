using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using NetMind.Core;
using static NetMind.Core.NetMindDefaults;

namespace NetMind.Workbench;

/// <summary>
/// 工作台应用入口。除资源字典外，这里只负责一件事：兜住未处理异常。
/// 工作台有大量 <c>async void</c> 事件处理器，任何一个抛出未捕获异常都会直接终止进程，
/// 长时间采集会话与未落盘状态随之丢失，且用户看不到任何原因。
/// </summary>
public partial class App : Application
{
    /// <summary>崩溃日志路径：与 settings.json 同在 %LocalAppData%\NetMind，不依赖当前工作区是否已加载。</summary>
    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        SettingsDirectoryName, LogsDirectoryName, "workbench-crash.log");

    /// <summary>连续崩溃熔断：同一异常在渲染或输入回路中反复抛出时，继续吞掉只会让界面卡在错误弹窗循环里。</summary>
    private const int RepeatedFailureLimit = 5;
    private static readonly TimeSpan RepeatedFailureWindow = TimeSpan.FromSeconds(30);
    private readonly Queue<DateTimeOffset> _recentFailures = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        base.OnStartup(e);
    }

    /// <summary>
    /// UI 线程未处理异常。默认吞掉并提示，让采集会话继续存活；
    /// 但短时间内反复失败时放行，避免陷入“弹窗—崩溃—弹窗”的死循环。
    /// </summary>
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Record("界面线程未处理异常", e.Exception);
        if (IsFailingRepeatedly())
        {
            Record("连续异常超过阈值", e.Exception, "已停止兜底，交由运行时终止进程。");
            return;
        }

        e.Handled = true;
        ShowFailureDialog(e.Exception);
    }

    /// <summary>后台任务未观察异常：标记为已观察，避免终结器线程按未观察异常策略终止进程。</summary>
    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Record("后台任务未观察异常", e.Exception);
        e.SetObserved();
    }

    /// <summary>非 UI 线程的致命异常：运行时即将终止进程，这里只能尽力留下可诊断的记录。</summary>
    private void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        Record("进程级未处理异常", e.ExceptionObject as Exception, $"IsTerminating={e.IsTerminating}");
    }

    private bool IsFailingRepeatedly()
    {
        var now = DateTimeOffset.UtcNow;
        while (_recentFailures.Count > 0 && now - _recentFailures.Peek() > RepeatedFailureWindow)
            _recentFailures.Dequeue();
        _recentFailures.Enqueue(now);
        return _recentFailures.Count > RepeatedFailureLimit;
    }

    private static void ShowFailureDialog(Exception exception)
    {
        try
        {
            MessageBox.Show(
                $"工作台遇到未处理的错误，已阻止程序退出。\n\n{exception.GetType().Name}：{exception.Message}\n\n" +
                $"当前界面状态可能不完整，建议停止采集后重启工作台。\n已记录到：{CrashLogPath}",
                "NetMind AI · 未处理错误", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch
        {
            // 界面已不可用时（例如关机过程中）不能因为弹窗失败再抛一次异常。
        }
    }

    /// <summary>
    /// 追加一条崩溃记录。异常文本可能带上被抓流量的 URL 或 Header，
    /// 因此与审计日志走同一套稳定脱敏，不把凭据原值落到诊断文件里。
    /// </summary>
    private static void Record(string category, Exception? exception, string? note = null)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
            var builder = new StringBuilder()
                .Append("═══ ").Append(DateTimeOffset.Now.ToString("O")).Append(" · ").AppendLine(category);
            if (note is not null) builder.AppendLine(note);
            builder.AppendLine(exception?.ToString() ?? "（无异常对象）").AppendLine();
            File.AppendAllText(CrashLogPath, WorkspaceStore.Redact(builder.ToString()), Encoding.UTF8);
        }
        catch
        {
            // 诊断记录是尽力而为：磁盘满或无写权限时绝不能再抛异常盖掉原始故障。
        }
    }
}
