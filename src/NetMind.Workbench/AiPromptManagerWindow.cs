using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetMind.Core;

namespace NetMind.Workbench;

/// <summary>
/// 提示词目录管理窗口：查看/编辑内置分析模板、新增自定义模板（自定义可删除、内置可恢复默认），
/// 维护快捷追问列表（增删改与排序）。全部修改先在内存中进行，点击“确定”后由调用方
/// 持久化到工作区 ai-prompts.json；“取消”丢弃全部修改。窗口无 XAML，全部代码构建，
/// 深色资源复用应用级样式（Card / SecondaryButton / DarkListBox 等）。
/// </summary>
public sealed class AiPromptManagerWindow : Window
{
    private const int MaximumDisplayNameChars = 60;
    private const int MaximumSystemPromptChars = 64_000;
    private const int MaximumRequirementChars = 8_000;
    private const int MaximumQuickFollowUps = 24;
    private const int MaximumQuickFollowUpChars = 500;

    private readonly List<AiPromptTemplate> _templates;
    private readonly List<string> _followUps;
    private readonly ListBox _templateList;
    private readonly ListBox _followUpList;
    private readonly TextBox _templateNameBox;
    private readonly TextBox _systemPromptBox;
    private readonly TextBox _requirementBox;
    private readonly TextBox _followUpBox;
    private readonly Button _deleteTemplateButton;
    private readonly Button _restoreBuiltInButton;
    private readonly Button _saveFollowUpButton;
    private readonly Button _deleteFollowUpButton;
    private readonly Button _moveUpButton;
    private readonly Button _moveDownButton;
    private readonly TextBlock _statusText;
    private bool _loadingTemplate;

    /// <summary>点击“确定”后生效的编辑结果；取消时为传入的原始目录。</summary>
    public AiPromptCatalog Catalog { get; private set; }

    public AiPromptManagerWindow(AiPromptCatalog catalog)
    {
        Catalog = catalog;
        _templates = [.. catalog.Templates];
        _followUps = [.. catalog.QuickFollowUps];

        Title = "提示词管理";
        Width = 1060;
        Height = 700;
        MinWidth = 860;
        MinHeight = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = GetBrush("BackgroundBrush");
        Foreground = GetBrush("TextBrush");

        _templateList = new ListBox
        {
            Style = (Style)FindResource("DarkListBox"),
            ItemContainerStyle = (Style)FindResource("DarkListItem")
        };
        _templateList.SelectionChanged += (_, _) => 载入模板编辑区();

        _followUpList = new ListBox
        {
            Style = (Style)FindResource("DarkListBox"),
            ItemContainerStyle = (Style)FindResource("DarkListItem")
        };
        _followUpList.SelectionChanged += (_, _) => 载入追问编辑区();

        _templateNameBox = new TextBox();
        _systemPromptBox = CreateEditorBox(minHeight: 200);
        _requirementBox = CreateEditorBox(minHeight: 80);
        _followUpBox = new TextBox();

        _deleteTemplateButton = new Button { Content = "删除自定义", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0) };
        _deleteTemplateButton.Click += 删除模板_Click;
        _restoreBuiltInButton = new Button { Content = "恢复内置", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0), ToolTip = "将选中的内置模板恢复为默认内容" };
        _restoreBuiltInButton.Click += 恢复内置_Click;
        var addTemplateButton = new Button { Content = "新增模板", Style = SecondaryStyle() };
        addTemplateButton.Click += 新增模板_Click;
        var saveTemplateButton = new Button { Content = "保存修改", Style = SecondaryStyle(), HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 6, 0, 6) };
        saveTemplateButton.Click += 保存模板_Click;

        _saveFollowUpButton = new Button { Content = "保存修改", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0) };
        _saveFollowUpButton.Click += 保存追问_Click;
        _deleteFollowUpButton = new Button { Content = "删除", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0) };
        _deleteFollowUpButton.Click += 删除追问_Click;
        _moveUpButton = new Button { Content = "上移", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0) };
        _moveUpButton.Click += (_, _) => 移动追问(-1);
        _moveDownButton = new Button { Content = "下移", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0) };
        _moveDownButton.Click += (_, _) => 移动追问(1);
        var addFollowUpButton = new Button { Content = "新增", Style = SecondaryStyle() };
        addFollowUpButton.Click += 新增追问_Click;

        _statusText = new TextBlock { Foreground = GetBrush("MutedBrush"), VerticalAlignment = VerticalAlignment.Center };

        var confirmButton = new Button { Content = "确定", Style = (Style)FindResource("PrimaryButton"), Margin = new Thickness(8, 0, 0, 0) };
        confirmButton.Click += 确定_Click;
        var cancelButton = new Button { Content = "取消", Style = SecondaryStyle(), Margin = new Thickness(8, 0, 0, 0), IsCancel = true };
        cancelButton.Click += (_, _) => DialogResult = false;

        var templateCard = new Border { Style = (Style)FindResource("Card") };
        var templateGrid = new Grid();
        templateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(230) });
        templateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14, GridUnitType.Pixel) });
        templateGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(templateCard, 0);
        templateGrid.Children.Add(templateCard);

        var listPanel = new DockPanel();
        listPanel.Children.Add(CreateHeader("分析模板", "内置模板可覆写；自定义模板可删除", Dock.Top));
        var templateListButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        templateListButtons.Children.Add(addTemplateButton);
        templateListButtons.Children.Add(_restoreBuiltInButton);
        templateListButtons.Children.Add(_deleteTemplateButton);
        DockPanel.SetDock(templateListButtons, Dock.Bottom);
        listPanel.Children.Add(templateListButtons);
        listPanel.Children.Add(_templateList);
        templateCard.Child = listPanel;

        var editorPanel = new DockPanel();
        editorPanel.Children.Add(CreateHeader("编辑选中模板", "系统提示随会话首条 system 消息发送；分析要求拼入首轮用户消息", Dock.Top));
        // 显式 Dock.Bottom：未设 dock 时默认 Left 且垂直拉伸，按钮会占满整列（历史缺陷根因）
        DockPanel.SetDock(saveTemplateButton, Dock.Bottom);
        editorPanel.Children.Add(saveTemplateButton);
        var editorScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 10, 0, 0) };
        var editorStack = new StackPanel();
        editorStack.Children.Add(CreateLabel("模板名称"));
        editorStack.Children.Add(_templateNameBox);
        editorStack.Children.Add(CreateLabel("系统提示", margin: new Thickness(0, 12, 0, 5)));
        editorStack.Children.Add(_systemPromptBox);
        editorStack.Children.Add(CreateLabel("分析要求", margin: new Thickness(0, 12, 0, 5)));
        editorStack.Children.Add(_requirementBox);
        editorScroll.Content = editorStack;
        editorPanel.Children.Add(editorScroll);
        Grid.SetColumn(editorPanel, 2);
        templateGrid.Children.Add(editorPanel);

        var followUpCard = new Border { Style = (Style)FindResource("Card") };
        var followUpPanel = new DockPanel();
        followUpPanel.Children.Add(CreateHeader("快捷追问", "会话完成后显示在聊天区下方的按钮，按此处顺序排列", Dock.Top));
        var followUpEdit = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        followUpEdit.Children.Add(_followUpBox);
        var followUpButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0), HorizontalAlignment = HorizontalAlignment.Right };
        followUpButtons.Children.Add(addFollowUpButton);
        followUpButtons.Children.Add(_saveFollowUpButton);
        followUpButtons.Children.Add(_deleteFollowUpButton);
        followUpButtons.Children.Add(_moveUpButton);
        followUpButtons.Children.Add(_moveDownButton);
        followUpEdit.Children.Add(followUpButtons);
        DockPanel.SetDock(followUpEdit, Dock.Bottom);
        followUpPanel.Children.Add(followUpEdit);
        followUpPanel.Children.Add(_followUpList);
        followUpCard.Child = followUpPanel;

        var bodyGrid = new Grid { Margin = new Thickness(20, 20, 20, 12) };
        bodyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
        bodyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12, GridUnitType.Pixel) });
        bodyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        bodyGrid.Children.Add(templateGrid);
        Grid.SetColumn(followUpCard, 2);
        bodyGrid.Children.Add(followUpCard);

        var bottomBar = new DockPanel { Margin = new Thickness(20, 0, 20, 18) };
        var confirmPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        confirmPanel.Children.Add(cancelButton);
        confirmPanel.Children.Add(confirmButton);
        DockPanel.SetDock(confirmPanel, Dock.Right);
        bottomBar.Children.Add(confirmPanel);
        bottomBar.Children.Add(_statusText);

        var root = new DockPanel();
        DockPanel.SetDock(bottomBar, Dock.Bottom);
        root.Children.Add(bottomBar);
        root.Children.Add(bodyGrid);
        Content = root;

        刷新模板列表(selectIndex: 0);
        刷新追问列表(selectIndex: 0);
    }

    private Style SecondaryStyle() => (Style)FindResource("SecondaryButton");
    private Brush GetBrush(string key) => FindResource(key) as Brush ?? Brushes.White;

    private static TextBox CreateEditorBox(double minHeight) => new()
    {
        AcceptsReturn = true,
        TextWrapping = TextWrapping.Wrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        VerticalContentAlignment = VerticalAlignment.Top,
        MinHeight = minHeight
    };

    private static TextBlock CreateLabel(string text, Thickness? margin = null) => new()
    {
        Text = text,
        FontSize = 11,
        Foreground = new SolidColorBrush(Color.FromRgb(0x87, 0x98, 0xA4)),
        Margin = margin ?? new Thickness(0, 0, 0, 5)
    };

    private static StackPanel CreateHeader(string title, string hint, Dock dock)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
        panel.Children.Add(new TextBlock { Text = title, FontSize = 15, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock
        {
            Text = hint,
            FontSize = 11.5,
            Foreground = new SolidColorBrush(Color.FromRgb(0x87, 0x98, 0xA4)),
            Margin = new Thickness(0, 4, 0, 0)
        });
        DockPanel.SetDock(panel, dock);
        return panel;
    }

    private void 设置状态(string message, string brushKey)
    {
        _statusText.Text = message;
        _statusText.Foreground = GetBrush(brushKey);
    }

    // ---------- 模板区 ----------

    private void 刷新模板列表(int selectIndex)
    {
        _templateList.ItemsSource = null;
        _templateList.ItemsSource = _templates;
        _templateList.DisplayMemberPath = null;
        if (_templateList.ItemTemplate is null)
            _templateList.ItemTemplate = CreateTemplateItemTemplate();
        var index = Math.Clamp(selectIndex, 0, _templates.Count - 1);
        _templateList.SelectedIndex = index;
        更新模板按钮状态();
    }

    private static DataTemplate CreateTemplateItemTemplate()
    {
        var factory = new FrameworkElementFactory(typeof(TextBlock));
        factory.SetValue(TextBlock.TextProperty, new System.Windows.Data.Binding
        {
            Converter = TemplateDisplayConverter.Instance
        });
        factory.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        return new DataTemplate { VisualTree = factory };
    }

    private sealed class TemplateDisplayConverter : System.Windows.Data.IValueConverter
    {
        public static readonly TemplateDisplayConverter Instance = new();
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
            value is AiPromptTemplate template
                ? template.Id.StartsWith("custom-", StringComparison.OrdinalIgnoreCase)
                    ? template.DisplayName + "（自定义）"
                    : template.DisplayName
                : string.Empty;
        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
            throw new NotSupportedException();
    }

    private void 载入模板编辑区()
    {
        if (_loadingTemplate || _templateList.SelectedItem is not AiPromptTemplate template) return;
        _loadingTemplate = true;
        try
        {
            _templateNameBox.Text = template.DisplayName;
            _systemPromptBox.Text = template.SystemPrompt;
            _requirementBox.Text = template.AnalysisRequirement;
        }
        finally { _loadingTemplate = false; }
        更新模板按钮状态();
    }

    private void 更新模板按钮状态()
    {
        var selected = _templateList.SelectedItem as AiPromptTemplate;
        var isCustom = selected is not null && selected.Id.StartsWith("custom-", StringComparison.OrdinalIgnoreCase);
        var isBuiltIn = selected is not null && !isCustom;
        _deleteTemplateButton.IsEnabled = isCustom && _templates.Count > 1;
        _restoreBuiltInButton.IsEnabled = isBuiltIn;
    }

    private void 新增模板_Click(object sender, RoutedEventArgs e)
    {
        var template = new AiPromptTemplate(
            AiPromptCatalogStore.NewCustomTemplateId(),
            "自定义模板",
            "你是 NetMind AI 的网络协议流程分析助手。只根据用户提供的流量事务证据回答；证据不足时明确写“证据不足”，不臆测未观察到的内容。",
            "请按本模板的分析要求，基于证据池中的流量事务给出结论。");
        _templates.Add(template);
        刷新模板列表(_templates.Count - 1);
        _templateNameBox.Focus();
        _templateNameBox.SelectAll();
        设置状态("已新增自定义模板，填写内容后点击“保存修改”", "MutedBrush");
    }

    private void 保存模板_Click(object sender, RoutedEventArgs e)
    {
        if (_templateList.SelectedItem is not AiPromptTemplate current) return;
        var name = _templateNameBox.Text.Trim();
        var system = _systemPromptBox.Text;
        var requirement = _requirementBox.Text.Trim();
        if (name.Length is < 1 or > MaximumDisplayNameChars)
        {
            设置状态($"模板名称不能为空，且不超过 {MaximumDisplayNameChars} 字", "RedBrush");
            return;
        }
        if (system.Length is < 1 or > MaximumSystemPromptChars)
        {
            设置状态($"系统提示不能为空，且不超过 {MaximumSystemPromptChars:N0} 字", "RedBrush");
            return;
        }
        if (requirement.Length is < 1 or > MaximumRequirementChars)
        {
            设置状态($"分析要求不能为空，且不超过 {MaximumRequirementChars:N0} 字", "RedBrush");
            return;
        }
        var index = _templates.IndexOf(current);
        _templates[index] = current with { DisplayName = name, SystemPrompt = system, AnalysisRequirement = requirement };
        刷新模板列表(index);
        设置状态($"模板“{name}”已保存修改（点“确定”后写入工作区）", "GreenBrush");
    }

    private void 删除模板_Click(object sender, RoutedEventArgs e)
    {
        if (_templateList.SelectedItem is not AiPromptTemplate current) return;
        if (_templates.Count <= 1)
        {
            设置状态("至少保留一个分析模板", "RedBrush");
            return;
        }
        var answer = MessageBox.Show(this, $"确认删除自定义模板“{current.DisplayName}”？点“确定”后生效。", "删除模板", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        var index = _templates.IndexOf(current);
        _templates.RemoveAt(index);
        刷新模板列表(Math.Min(index, _templates.Count - 1));
        设置状态("已删除自定义模板", "GreenBrush");
    }

    private void 恢复内置_Click(object sender, RoutedEventArgs e)
    {
        if (_templateList.SelectedItem is not AiPromptTemplate current) return;
        var builtIn = AiPromptTemplate.All.FirstOrDefault(item => string.Equals(item.Id, current.Id, StringComparison.OrdinalIgnoreCase));
        if (builtIn is null)
        {
            设置状态("该模板不是内置模板，无法恢复", "RedBrush");
            return;
        }
        var index = _templates.IndexOf(current);
        _templates[index] = builtIn;
        刷新模板列表(index);
        设置状态($"内置模板“{builtIn.DisplayName}”已恢复默认内容", "GreenBrush");
    }

    // ---------- 快捷追问区 ----------

    private void 刷新追问列表(int selectIndex)
    {
        _followUpList.ItemsSource = null;
        _followUpList.ItemsSource = _followUps;
        if (_followUps.Count > 0) _followUpList.SelectedIndex = Math.Clamp(selectIndex, 0, _followUps.Count - 1);
        更新追问按钮状态();
    }

    private void 载入追问编辑区()
    {
        if (_followUpList.SelectedItem is not string followUp) return;
        _followUpBox.Text = followUp;
        更新追问按钮状态();
    }

    private void 更新追问按钮状态()
    {
        var index = _followUpList.SelectedIndex;
        _saveFollowUpButton.IsEnabled = _deleteFollowUpButton.IsEnabled = index >= 0;
        _moveUpButton.IsEnabled = index > 0;
        _moveDownButton.IsEnabled = index >= 0 && index < _followUps.Count - 1;
    }

    private void 新增追问_Click(object sender, RoutedEventArgs e)
    {
        var text = _followUpBox.Text.Trim();
        if (text.Length == 0)
        {
            设置状态("快捷追问内容不能为空", "RedBrush");
            return;
        }
        if (text.Length > MaximumQuickFollowUpChars)
        {
            设置状态($"快捷追问不超过 {MaximumQuickFollowUpChars} 字", "RedBrush");
            return;
        }
        if (_followUps.Count >= MaximumQuickFollowUps)
        {
            设置状态($"快捷追问最多 {MaximumQuickFollowUps} 条", "RedBrush");
            return;
        }
        if (_followUps.Contains(text, StringComparer.Ordinal))
        {
            设置状态("已存在相同的快捷追问", "RedBrush");
            return;
        }
        _followUps.Add(text);
        刷新追问列表(_followUps.Count - 1);
        _followUpBox.Clear();
        设置状态("已新增快捷追问（点“确定”后写入工作区）", "GreenBrush");
    }

    private void 保存追问_Click(object sender, RoutedEventArgs e)
    {
        if (_followUpList.SelectedIndex is var index && index < 0) return;
        var text = _followUpBox.Text.Trim();
        if (text.Length is 0 or > MaximumQuickFollowUpChars)
        {
            设置状态($"快捷追问不能为空，且不超过 {MaximumQuickFollowUpChars} 字", "RedBrush");
            return;
        }
        for (var i = 0; i < _followUps.Count; i++)
        {
            if (i != index && string.Equals(_followUps[i], text, StringComparison.Ordinal))
            {
                设置状态("已存在相同的快捷追问", "RedBrush");
                return;
            }
        }
        _followUps[index] = text;
        刷新追问列表(index);
        设置状态("快捷追问已保存修改", "GreenBrush");
    }

    private void 删除追问_Click(object sender, RoutedEventArgs e)
    {
        var index = _followUpList.SelectedIndex;
        if (index < 0) return;
        _followUps.RemoveAt(index);
        刷新追问列表(Math.Min(index, _followUps.Count - 1));
        _followUpBox.Clear();
        设置状态("已删除快捷追问", "GreenBrush");
    }

    private void 移动追问(int delta)
    {
        var index = _followUpList.SelectedIndex;
        var target = index + delta;
        if (index < 0 || target < 0 || target >= _followUps.Count) return;
        (_followUps[index], _followUps[target]) = (_followUps[target], _followUps[index]);
        刷新追问列表(target);
    }

    // ---------- 确认 ----------

    private void 确定_Click(object sender, RoutedEventArgs e)
    {
        if (_templates.Count == 0)
        {
            设置状态("至少保留一个分析模板", "RedBrush");
            return;
        }
        foreach (var template in _templates)
        {
            if (string.IsNullOrWhiteSpace(template.DisplayName) || string.IsNullOrWhiteSpace(template.SystemPrompt) || string.IsNullOrWhiteSpace(template.AnalysisRequirement))
            {
                设置状态($"模板“{template.DisplayName}”存在空内容，请补全后再确认", "RedBrush");
                return;
            }
        }
        Catalog = new AiPromptCatalog(_templates, _followUps);
        DialogResult = true;
    }
}
