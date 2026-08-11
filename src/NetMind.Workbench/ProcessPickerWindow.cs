using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace NetMind.Workbench;

/// <summary>
/// 按进程采集的进程选择窗口：列出本机进程（名称/PID/可执行路径），支持关键字过滤与刷新；
/// 双击进程行（或选中后点“抓取该进程”）即确定选择，由调用方启动仅落库该进程事务的静默抓包。
/// 窗口无 XAML，全部代码构建，深色资源复用应用级样式。
/// </summary>
public sealed class ProcessPickerWindow : Window
{
    private sealed record ProcessRow(string Name, int Pid, string Path);

    private readonly TextBox _searchBox;
    private readonly DataGrid _processGrid;
    private readonly TextBlock _statusText;
    private List<ProcessRow> _allRows = [];

    /// <summary>双击或确认后选中的进程（名称/PID/路径）；取消时为 null。</summary>
    public (string Name, int Pid, string Path)? SelectedProcess { get; private set; }

    public ProcessPickerWindow()
    {
        Title = "选择要抓取的进程";
        Width = 780;
        Height = 540;
        MinWidth = 620;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = (Brush)FindResource("BackgroundBrush");
        Foreground = (Brush)FindResource("TextBrush");

        _searchBox = new TextBox { Width = 260, ToolTip = "按进程名、PID 或路径过滤" };
        _searchBox.TextChanged += (_, _) => ApplyFilter();
        var refreshButton = new Button { Content = "刷新", Style = (Style)FindResource("SecondaryButton"), Margin = new Thickness(8, 0, 0, 0) };
        refreshButton.Click += (_, _) => 载入进程列表();
        var captureButton = new Button { Content = "抓取该进程", Style = (Style)FindResource("PrimaryButton") };
        captureButton.Click += (_, _) => 确认选择();
        var cancelButton = new Button { Content = "取消", Style = (Style)FindResource("SecondaryButton"), Margin = new Thickness(8, 0, 0, 0), IsCancel = true };
        cancelButton.Click += (_, _) => DialogResult = false;

        _statusText = new TextBlock
        {
            Text = "双击进程行即开始抓取该进程的流量（需静默抓包模式）",
            Foreground = (Brush)FindResource("MutedBrush"),
            FontSize = 11.5,
            VerticalAlignment = VerticalAlignment.Center,
        };

        _processGrid = CreateProcessGrid();
        _processGrid.MouseDoubleClick += (_, _) => 确认选择();

        var toolbar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        toolbar.Children.Add(new TextBlock { Text = "进程关键字", Foreground = (Brush)FindResource("MutedBrush"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
        toolbar.Children.Add(_searchBox);
        toolbar.Children.Add(refreshButton);
        toolbar.Children.Add(_statusText);

        var footer = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        footer.Children.Add(captureButton);
        footer.Children.Add(cancelButton);

        var root = new DockPanel { Margin = new Thickness(18) };
        DockPanel.SetDock(toolbar, Dock.Top);
        root.Children.Add(toolbar);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(_processGrid);
        Content = root;

        Loaded += (_, _) => 载入进程列表();
    }

    private void 载入进程列表()
    {
        var rows = new List<ProcessRow>();
        foreach (var process in Process.GetProcesses())
        {
            string path;
            try { path = process.MainModule?.FileName ?? "—"; }
            catch { path = "—"; } // 跨位数或受保护进程无法读取模块路径，不阻断列表
            rows.Add(new ProcessRow(process.ProcessName, process.Id, path));
            process.Dispose();
        }
        _allRows = rows.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ToList();
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = _searchBox.Text.Trim();
        var visible = query.Length == 0
            ? _allRows
            : _allRows.Where(row => row.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                                    row.Pid.ToString().Contains(query, StringComparison.Ordinal) ||
                                    row.Path.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        _processGrid.ItemsSource = visible;
        _statusText.Text = query.Length == 0
            ? $"共 {visible.Count} 个进程 · 双击进程行即开始抓取该进程的流量"
            : $"匹配 {visible.Count} / {_allRows.Count} 个进程 · 双击进程行即开始抓取该进程的流量";
    }

    private void 确认选择()
    {
        if (_processGrid.SelectedItem is not ProcessRow row)
        {
            _statusText.Text = "请先选择要抓取的进程";
            return;
        }
        SelectedProcess = (row.Name, row.Pid, row.Path);
        DialogResult = true;
    }

    private static DataGrid CreateProcessGrid()
    {
        var grid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            CanUserAddRows = false,
            SelectionMode = DataGridSelectionMode.Single,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            FontSize = 12,
            RowHeight = 26,
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(Color.FromRgb(197, 210, 217)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(36, 56, 74)),
            BorderThickness = new Thickness(1),
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            HorizontalGridLinesBrush = new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF)),
            RowBackground = Brushes.Transparent,
            AlternatingRowBackground = new SolidColorBrush(Color.FromArgb(0x14, 0xFF, 0xFF, 0xFF)),
        };
        grid.ColumnHeaderStyle = new Style(typeof(DataGridColumnHeader))
        {
            Setters =
            {
                new Setter(Control.BackgroundProperty, new SolidColorBrush(Color.FromRgb(19, 31, 44))),
                new Setter(Control.ForegroundProperty, new SolidColorBrush(Color.FromRgb(135, 152, 164))),
                new Setter(Control.PaddingProperty, new Thickness(8, 4, 8, 4)),
                new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF))),
                new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 1, 1)),
            }
        };
        // 宽度必须用 DataGridLength：它拒绝 NaN 与无穷大（两者都抛「不应允许无限值」），
        // 因此不能沿用 FrameworkElement.Width 那套「NaN 表示自动」的约定。
        DataGridTextColumn Column(string header, string binding, DataGridLength width) => new()
        {
            Header = header,
            Binding = new System.Windows.Data.Binding(binding),
            Width = width,
            IsReadOnly = true,
        };
        grid.Columns.Add(Column("进程名", nameof(ProcessRow.Name), new DataGridLength(180)));
        grid.Columns.Add(Column("PID", nameof(ProcessRow.Pid), new DataGridLength(70)));
        grid.Columns.Add(Column("可执行路径", nameof(ProcessRow.Path), new DataGridLength(1, DataGridLengthUnitType.Star)));
        return grid;
    }
}
