using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetMind.Core;

namespace NetMind.Workbench;

/// <summary>采集自检结果窗口：逐项展示状态、结论和修复提示，并支持复制完整报告。</summary>
public sealed class CaptureHealthWindow : Window
{
    private sealed record HealthRow(string State, string Item, string Result, string Detail, Brush StateBrush);

    public CaptureHealthWindow(CaptureHealthReport report)
    {
        Title = "采集链路自检";
        Width = 880;
        Height = 560;
        MinWidth = 700;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = (Brush)FindResource("BackgroundBrush");
        Foreground = (Brush)FindResource("TextBrush");

        var rows = report.Items.Select(item => new HealthRow(
            StateText(item.Level), item.Name, item.Summary, item.Detail, StateBrush(item.Level))).ToArray();
        var grid = new DataGrid
        {
            ItemsSource = rows,
            AutoGenerateColumns = false,
            IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Single,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            CanUserAddRows = false,
            CanUserDeleteRows = false,
            EnableRowVirtualization = true
        };
        grid.Columns.Add(new DataGridTextColumn
        {
            Header = "状态", Binding = new System.Windows.Data.Binding(nameof(HealthRow.State)), Width = 72,
            ElementStyle = CreateStateStyle()
        });
        grid.Columns.Add(new DataGridTextColumn { Header = "检查项", Binding = new System.Windows.Data.Binding(nameof(HealthRow.Item)), Width = 130 });
        grid.Columns.Add(new DataGridTextColumn { Header = "结果", Binding = new System.Windows.Data.Binding(nameof(HealthRow.Result)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridTextColumn { Header = "说明 / 建议", Binding = new System.Windows.Data.Binding(nameof(HealthRow.Detail)), Width = new DataGridLength(1.2, DataGridLengthUnitType.Star) });

        var summary = new TextBlock
        {
            Text = $"结论：{StateText(report.OverallLevel)} · {report.CheckedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Foreground = StateBrush(report.OverallLevel),
            Margin = new Thickness(0, 0, 0, 12)
        };
        var copy = new Button { Content = "复制完整报告", Style = (Style)FindResource("SecondaryButton") };
        copy.Click += (_, _) =>
        {
            Clipboard.SetText(report.ToPlainText());
            copy.Content = "已复制";
        };
        var close = new Button
        {
            Content = "关闭", Style = (Style)FindResource("PrimaryButton"), Margin = new Thickness(8, 0, 0, 0),
            IsCancel = true
        };
        close.Click += (_, _) => Close();
        var footer = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        footer.Children.Add(copy);
        footer.Children.Add(close);

        var root = new DockPanel { Margin = new Thickness(18) };
        DockPanel.SetDock(summary, Dock.Top);
        root.Children.Add(summary);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(grid);
        Content = root;
    }

    private Style CreateStateStyle()
    {
        var style = new Style(typeof(TextBlock));
        style.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.SemiBold));
        style.Setters.Add(new Setter(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center));
        style.Setters.Add(new Setter(TextBlock.ForegroundProperty, new System.Windows.Data.Binding(nameof(HealthRow.StateBrush))));
        return style;
    }

    private Brush StateBrush(CaptureHealthLevel level) => (Brush)FindResource(level switch
    {
        CaptureHealthLevel.Passed => "GreenBrush",
        CaptureHealthLevel.Warning => "AmberBrush",
        CaptureHealthLevel.Failed => "RedBrush",
        _ => "MutedBrush"
    });

    private static string StateText(CaptureHealthLevel level) => level switch
    {
        CaptureHealthLevel.Passed => "通过",
        CaptureHealthLevel.Warning => "注意",
        CaptureHealthLevel.Failed => "失败",
        _ => "信息"
    };
}
