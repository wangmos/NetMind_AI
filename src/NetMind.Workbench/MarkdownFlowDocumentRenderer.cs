using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;

namespace NetMind.Workbench;

internal static partial class MarkdownFlowDocumentRenderer
{
    private static readonly Brush TextBrush = new SolidColorBrush(Color.FromRgb(206, 217, 223));
    private static readonly Brush MutedBrush = new SolidColorBrush(Color.FromRgb(135, 152, 164));
    private static readonly Brush AccentBrush = new SolidColorBrush(Color.FromRgb(121, 184, 179));
    private static readonly Brush RaisedBrush = new SolidColorBrush(Color.FromRgb(23, 37, 52));
    private static readonly Brush BorderBrush = new SolidColorBrush(Color.FromRgb(36, 56, 74));
    private static readonly Brush CodeKeywordBrush = new SolidColorBrush(Color.FromRgb(174, 146, 174));
    private static readonly Brush CodeStringBrush = new SolidColorBrush(Color.FromRgb(190, 151, 132));
    private static readonly Brush CodeCommentBrush = new SolidColorBrush(Color.FromRgb(116, 148, 104));
    private static readonly Brush CodeNumberBrush = new SolidColorBrush(Color.FromRgb(164, 187, 154));
    private const int MaximumHighlightedCodeCharacters = 120_000;
    private const int MaximumHighlightedTokens = 12_000;

    public static FlowDocument Render(string markdown)
    {
        var document = new FlowDocument
        {
            PagePadding = new Thickness(0),
            FontFamily = new FontFamily("Microsoft YaHei UI"),
            FontSize = 13,
            Foreground = TextBrush,
            LineHeight = 22
        };
        // 归一化换行：先处理 \r\n，再把单独出现的 \r 视为换行（部分模型输出只有 \r）。
        var lines = (markdown ?? string.Empty)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');
        for (var index = 0; index < lines.Length;)
        {
            var line = lines[index];
            if (FencePrefix(line) is { Length: > 0 } fence)
            {
                var language = line.TrimStart()[fence.Length..].Trim();
                var code = new StringBuilder();
                index++;
                // 结束围栏须与开始围栏同类；宽松匹配只要求至少三个同符号字符，避免代码内容误闭合。
                while (index < lines.Length && !lines[index].TrimStart().StartsWith(fence[..3], StringComparison.Ordinal))
                {
                    if (code.Length > 0) code.AppendLine();
                    code.Append(lines[index++]);
                }
                if (index < lines.Length) index++;
                var codeParagraph = new Paragraph
                {
                    FontFamily = new FontFamily("Cascadia Mono"), FontSize = 12, Background = RaisedBrush,
                    Padding = new Thickness(12), Margin = new Thickness(0, 8, 0, 10), BorderBrush = BorderBrush,
                    BorderThickness = new Thickness(1)
                };
                if (!string.IsNullOrWhiteSpace(language))
                    codeParagraph.Inlines.Add(new Run(language + Environment.NewLine)
                    {
                        Foreground = AccentBrush,
                        FontWeight = FontWeights.SemiBold
                    });
                AddHighlightedCode(codeParagraph.Inlines, code.ToString(), language);
                document.Blocks.Add(codeParagraph);
                continue;
            }
            if (index + 1 < lines.Length && IsTableSeparator(lines[index + 1]) && line.Contains('|'))
            {
                index = AddTable(document, lines, index);
                continue;
            }
            var trimmed = line.Trim();
            if (trimmed.Length == 0) { index++; continue; }
            if (HorizontalRule().IsMatch(trimmed))
            {
                document.Blocks.Add(new Paragraph { BorderBrush = BorderBrush, BorderThickness = new Thickness(0, 0, 0, 1), Margin = new Thickness(0, 9, 0, 12) });
                index++;
                continue;
            }
            var heading = Heading().Match(line);
            if (heading.Success)
            {
                var level = heading.Groups[1].Length;
                var paragraph = CreateParagraph(heading.Groups[2].Value, new Thickness(0, level == 1 ? 4 : 12, 0, 7));
                paragraph.FontSize = level switch { 1 => 23, 2 => 19, 3 => 16, _ => 14 };
                paragraph.FontWeight = FontWeights.SemiBold;
                paragraph.Foreground = level <= 2 ? AccentBrush : TextBrush;
                document.Blocks.Add(paragraph);
                index++;
                continue;
            }
            var quote = BlockQuote().Match(line);
            if (quote.Success)
            {
                var paragraph = CreateParagraph(quote.Groups[1].Value, new Thickness(0, 6, 0, 8));
                paragraph.Foreground = MutedBrush;
                paragraph.BorderBrush = AccentBrush;
                paragraph.BorderThickness = new Thickness(3, 0, 0, 0);
                paragraph.Padding = new Thickness(12, 4, 0, 4);
                document.Blocks.Add(paragraph);
                index++;
                continue;
            }
            var unordered = UnorderedList().Match(line);
            var ordered = OrderedList().Match(line);
            if (unordered.Success || ordered.Success)
            {
                // 有序列表：组 1 数字、组 2 分隔符（. ) 或中文顿号）、组 3 内容；标记保留原文分隔符。
                var content = unordered.Success ? unordered.Groups[1].Value : ordered.Groups[3].Value;
                var marker = unordered.Success ? "•  " : ordered.Groups[1].Value + ordered.Groups[2].Value + "  ";
                var paragraph = new Paragraph { Margin = new Thickness(15, 2, 0, 4), TextIndent = -14 };
                paragraph.Inlines.Add(new Run(marker) { Foreground = AccentBrush, FontWeight = FontWeights.SemiBold });
                AddInlineMarkdown(paragraph.Inlines, content);
                document.Blocks.Add(paragraph);
                index++;
                continue;
            }
            var normal = CreateParagraph(line, new Thickness(0, 3, 0, 7));
            document.Blocks.Add(normal);
            index++;
        }
        if (document.Blocks.Count == 0) document.Blocks.Add(new Paragraph(new Run("暂无模型分析结果。") { Foreground = MutedBrush }));
        return document;
    }

    private static Paragraph CreateParagraph(string text, Thickness margin)
    {
        var paragraph = new Paragraph { Margin = margin };
        AddInlineMarkdown(paragraph.Inlines, text);
        return paragraph;
    }

    private static void AddInlineMarkdown(InlineCollection inlines, string text)
    {
        var cursor = 0;
        foreach (Match match in InlineToken().Matches(text))
        {
            if (match.Index > cursor) inlines.Add(new Run(text[cursor..match.Index]));
            var token = match.Value;
            if (token.StartsWith("**", StringComparison.Ordinal)) inlines.Add(new Run(token[2..^2]) { FontWeight = FontWeights.Bold });
            else if (token.StartsWith('`')) inlines.Add(new Run(token[1..^1]) { FontFamily = new FontFamily("Cascadia Mono"), Background = RaisedBrush, Foreground = AccentBrush });
            else inlines.Add(new Run(token[1..^1]) { FontStyle = FontStyles.Italic });
            cursor = match.Index + match.Length;
        }
        if (cursor < text.Length) inlines.Add(new Run(text[cursor..]));
    }

    /// <summary>为常见模型输出语言做轻量语法着色；超大代码块退回单 Run，避免创建海量 WPF 元素。</summary>
    private static void AddHighlightedCode(InlineCollection inlines, string code, string language)
    {
        var normalized = language.Trim().ToLowerInvariant();
        var syntax = normalized switch
        {
            "python" or "py" => PythonSyntax,
            "javascript" or "js" or "typescript" or "ts" or "jsx" or "tsx" => JavaScriptSyntax,
            "c#" or "csharp" or "cs" => CSharpSyntax,
            "json" or "jsonc" => JsonSyntax,
            "bash" or "sh" or "shell" or "powershell" or "ps1" => ShellSyntax,
            _ => null
        };
        if (syntax is null || code.Length > MaximumHighlightedCodeCharacters)
        {
            inlines.Add(new Run(code) { Foreground = TextBrush });
            return;
        }

        var cursor = 0;
        var tokenCount = 0;
        foreach (Match match in syntax.Matches(code))
        {
            if (++tokenCount > MaximumHighlightedTokens) break;
            if (match.Index > cursor)
                inlines.Add(new Run(code[cursor..match.Index]) { Foreground = TextBrush });
            var brush = match.Groups["comment"].Success ? CodeCommentBrush
                : match.Groups["string"].Success ? CodeStringBrush
                : match.Groups["number"].Success ? CodeNumberBrush
                : CodeKeywordBrush;
            inlines.Add(new Run(match.Value) { Foreground = brush });
            cursor = match.Index + match.Length;
        }
        if (cursor < code.Length) inlines.Add(new Run(code[cursor..]) { Foreground = TextBrush });
    }

    private static int AddTable(FlowDocument document, string[] lines, int headerIndex)
    {
        var headers = SplitTableRow(lines[headerIndex]);
        var rows = new List<string[]>();
        var index = headerIndex + 2;
        while (index < lines.Length && lines[index].Contains('|') && !string.IsNullOrWhiteSpace(lines[index])) rows.Add(SplitTableRow(lines[index++]));
        var columnCount = Math.Max(headers.Length, rows.Count == 0 ? 0 : rows.Max(row => row.Length));
        var table = new Table { CellSpacing = 0, Margin = new Thickness(0, 8, 0, 12), BorderBrush = BorderBrush, BorderThickness = new Thickness(1) };
        for (var column = 0; column < columnCount; column++) table.Columns.Add(new TableColumn());
        var group = new TableRowGroup();
        var headerRow = new TableRow { Background = RaisedBrush, FontWeight = FontWeights.SemiBold, Foreground = AccentBrush };
        foreach (var cell in Pad(headers, columnCount)) headerRow.Cells.Add(CreateCell(cell));
        group.Rows.Add(headerRow);
        foreach (var values in rows)
        {
            var row = new TableRow();
            foreach (var cell in Pad(values, columnCount)) row.Cells.Add(CreateCell(cell));
            group.Rows.Add(row);
        }
        table.RowGroups.Add(group);
        document.Blocks.Add(table);
        return index;
    }

    private static TableCell CreateCell(string text)
    {
        var paragraph = CreateParagraph(text, new Thickness(0));
        return new TableCell(paragraph) { Padding = new Thickness(8, 6, 8, 6), BorderBrush = BorderBrush, BorderThickness = new Thickness(0, 0, 1, 1) };
    }

    private static string[] Pad(string[] values, int count) => Enumerable.Range(0, count).Select(index => index < values.Length ? values[index] : string.Empty).ToArray();
    private static string[] SplitTableRow(string line) => line.Trim().Trim('|').Split('|').Select(cell => cell.Trim()).ToArray();
    // 分隔行宽松识别：模型常输出 |--| 或 | --- | 等少于三个短横的变体；至少一个短横即视为表格分隔。
    private static bool IsTableSeparator(string line) => TableSeparator().IsMatch(line.Trim());

    /// <summary>行首代码围栏前缀：```（至少三个反引号）或 ~~~（至少三个波浪号）；无围栏返回空串。</summary>
    private static string FencePrefix(string line)
    {
        var trimmed = line.TrimStart();
        foreach (var candidate in new[] { "```", "~~~" })
            if (trimmed.StartsWith(candidate, StringComparison.Ordinal)) return candidate;
        return string.Empty;
    }

    [GeneratedRegex("^(#{1,6})\\s+(.+)$")]
    private static partial Regex Heading();
    [GeneratedRegex("^\\s*>\\s?(.*)$")]
    private static partial Regex BlockQuote();
    [GeneratedRegex("^\\s*[-+*]\\s+(.+)$")]
    private static partial Regex UnorderedList();
    [GeneratedRegex("^\\s*(\\d+)([.)、])\\s*(.+)$")]
    private static partial Regex OrderedList();
    [GeneratedRegex("^(?:-{3,}|_{3,}|\\*{3,})$")]
    private static partial Regex HorizontalRule();
    [GeneratedRegex("(?:\\*\\*.+?\\*\\*|`.+?`|(?<!\\*)\\*[^*]+?\\*)")]
    private static partial Regex InlineToken();
    [GeneratedRegex("^\\|?\\s*:?-+:?\\s*(?:\\|\\s*:?-+:?\\s*)+\\|?$")]
    private static partial Regex TableSeparator();

    private static readonly Regex PythonSyntax = new(
        "(?<comment>#[^\\r\\n]*)|(?<string>'''[\\s\\S]*?'''|\\\"\\\"\\\"[\\s\\S]*?\\\"\\\"\\\"|\\\"(?:\\\\.|[^\\\"\\\\])*\\\"|'(?:\\\\.|[^'\\\\])*')|(?<keyword>\\b(?:and|as|assert|async|await|break|class|continue|def|del|elif|else|except|False|finally|for|from|global|if|import|in|is|lambda|None|nonlocal|not|or|pass|raise|return|True|try|while|with|yield)\\b)|(?<number>\\b(?:0[xX][0-9a-fA-F]+|\\d+(?:\\.\\d+)?)\\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex JavaScriptSyntax = new(
        "(?<comment>//[^\\r\\n]*|/\\*[\\s\\S]*?\\*/)|(?<string>`(?:\\\\.|[^`\\\\])*`|\\\"(?:\\\\.|[^\\\"\\\\])*\\\"|'(?:\\\\.|[^'\\\\])*')|(?<keyword>\\b(?:async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|false|finally|for|from|function|get|if|import|in|instanceof|let|new|null|of|return|set|static|super|switch|this|throw|true|try|typeof|undefined|var|void|while|with|yield)\\b)|(?<number>\\b(?:0[xX][0-9a-fA-F]+|\\d+(?:\\.\\d+)?)\\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CSharpSyntax = new(
        "(?<comment>//[^\\r\\n]*|/\\*[\\s\\S]*?\\*/)|(?<string>[$@]*\\\"(?:\\\\.|\\\"\\\"|[^\\\"])*\\\"|'(?:\\\\.|[^'\\\\])')|(?<keyword>\\b(?:abstract|as|async|await|base|bool|break|byte|case|catch|char|checked|class|const|continue|decimal|default|delegate|do|double|else|enum|event|explicit|extern|false|finally|fixed|float|for|foreach|if|implicit|in|int|interface|internal|is|lock|long|namespace|new|null|object|operator|out|override|params|private|protected|public|readonly|record|ref|required|return|sbyte|sealed|short|sizeof|stackalloc|static|string|struct|switch|this|throw|true|try|typeof|uint|ulong|unchecked|unsafe|ushort|using|var|virtual|void|volatile|while)\\b)|(?<number>\\b(?:0[xX][0-9a-fA-F]+|\\d+(?:\\.\\d+)?)\\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex JsonSyntax = new(
        "(?<string>\\\"(?:\\\\.|[^\\\"\\\\])*\\\")|(?<keyword>\\b(?:true|false|null)\\b)|(?<number>-?\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ShellSyntax = new(
        "(?<comment>#[^\\r\\n]*)|(?<string>\\\"(?:\\\\.|[^\\\"\\\\])*\\\"|'[^']*')|(?<keyword>\\b(?:case|do|done|elif|else|esac|fi|for|foreach|function|if|in|param|return|select|switch|then|until|while)\\b)|(?<number>\\b\\d+(?:\\.\\d+)?\\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
}
