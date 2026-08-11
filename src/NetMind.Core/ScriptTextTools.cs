namespace NetMind.Core;

/// <summary>
/// 脚本编辑器的纯文本变换：注释切换、保守整理格式、可折叠区域识别。
///
/// 之所以放在 Core 而不是工作台：这些函数会直接改用户写了一半的脚本，
/// 一旦改坏就是数据损坏，必须能被冒烟测试覆盖（<c>--script-text-only</c>）。
/// 输入输出一律用 \n 换行，不处理 \r\n——编辑器读出来的就是 \n。
/// </summary>
public static class ScriptTextTools
{
    /// <summary>整理格式时把行首制表符展开成几个空格。</summary>
    public const int IndentSpaces = 4;

    private const string CommentPrefix = "# ";

    /// <summary>
    /// 切换 [startLine, endLine] 闭区间的行注释（Ctrl+/）。
    ///
    /// 语义与主流编辑器一致：范围内所有非空行都已注释则整体取消，否则整体注释。
    /// 加注释时统一插在这批行的<b>最小缩进处</b>而不是行首，这样 Python 的缩进结构不会被破坏。
    /// 空行不动——给空行加 <c>#</c> 只会让 diff 变脏。
    /// </summary>
    public static string ToggleComment(string text, int startLine, int endLine)
    {
        var lines = SplitLines(text);
        if (lines.Length == 0) return text;
        startLine = Math.Clamp(startLine, 0, lines.Length - 1);
        endLine = Math.Clamp(endLine, startLine, lines.Length - 1);

        var payload = new List<int>();
        for (var index = startLine; index <= endLine; index++)
            if (lines[index].Trim().Length > 0) payload.Add(index);
        if (payload.Count == 0) return text;

        var allCommented = payload.All(index => lines[index].TrimStart().StartsWith('#'));
        if (allCommented)
        {
            foreach (var index in payload) lines[index] = Uncomment(lines[index]);
        }
        else
        {
            var column = payload.Min(index => lines[index].Length - lines[index].TrimStart().Length);
            foreach (var index in payload)
                lines[index] = lines[index][..column] + CommentPrefix + lines[index][column..];
        }
        return string.Join('\n', lines);
    }

    private static string Uncomment(string line)
    {
        var indent = line.Length - line.TrimStart().Length;
        var rest = line[indent..];
        rest = rest[1..]; // 去掉 '#'
        // 只吃掉一个紧跟的空格：多吃会把 "#   缩进注释" 的对齐弄乱。
        if (rest.StartsWith(' ')) rest = rest[1..];
        return line[..indent] + rest;
    }

    /// <summary>
    /// 保守整理格式。刻意只做<b>不改变语义</b>的事：
    /// 行首制表符展开为空格、去行尾空白、连续空行压到最多两行、结尾恰好一个换行。
    ///
    /// 不做重排、不动运算符空格、不碰行首之后的制表符——Python 的缩进就是语法，
    /// 而且字符串字面量里的空白是数据。三引号字符串内部的行原样保留，一个字符都不动。
    /// </summary>
    public static string Format(string text)
    {
        var lines = SplitLines(text);
        var result = new List<string>(lines.Length);
        var blankRun = 0;
        string? tripleQuote = null;
        foreach (var raw in lines)
        {
            if (tripleQuote is not null)
            {
                result.Add(raw); // 多行字符串内部：原样保留
                blankRun = 0;
                if (ClosesTripleQuote(raw, tripleQuote)) tripleQuote = null;
                continue;
            }

            // 必须先判断这行是否打开了三引号：打开三引号的那一行，引号之后的内容
            // 已经属于字符串数据，行尾空白不能去——去了就改了字符串的值。
            var expanded = ExpandLeadingTabs(raw);
            var opens = OpenTripleQuote(expanded);
            var line = opens is null ? expanded.TrimEnd() : expanded;
            if (line.Length == 0)
            {
                // 连续空行压到最多两行；开头的空行整体丢掉。
                if (result.Count == 0) continue;
                if (++blankRun > 2) continue;
                result.Add(string.Empty);
                continue;
            }
            blankRun = 0;
            result.Add(line);
            tripleQuote = opens;
        }
        while (result.Count > 0 && result[^1].Length == 0) result.RemoveAt(result.Count - 1);
        return string.Join('\n', result);
    }

    private static string ExpandLeadingTabs(string line)
    {
        var index = 0;
        while (index < line.Length && line[index] == '\t') index++;
        return index == 0 ? line : new string(' ', index * IndentSpaces) + line[index..];
    }

    /// <summary>返回本行遗留未闭合的三引号（<c>"""</c> 或 <c>'''</c>），没有则 null。</summary>
    private static string? OpenTripleQuote(string line)
    {
        string? open = null;
        for (var index = 0; index + 3 <= line.Length; index++)
        {
            var token = line.Substring(index, 3);
            if (token is not ("\"\"\"" or "'''")) continue;
            if (open is null) open = token;
            else if (open == token) open = null;
            index += 2;
        }
        return open;
    }

    private static bool ClosesTripleQuote(string line, string token) =>
        line.Contains(token, StringComparison.Ordinal);

    /// <summary>可折叠区域：<paramref name="Header"/> 是带冒号的起始行，区域体为 [Header+1, End]。</summary>
    public readonly record struct FoldRegion(int Header, int End)
    {
        /// <summary>被折叠隐藏的行数。</summary>
        public int HiddenLineCount => End - Header;
    }

    /// <summary>
    /// 按缩进识别可折叠区域：以冒号结尾的行（def / class / if / for / with / try…）
    /// 加上其后所有缩进更深的行。区域末尾的空行不计入，否则折叠后会留下突兀的空白。
    /// 少于两行体的区域不返回——折叠一行没有意义。
    /// </summary>
    public static IReadOnlyList<FoldRegion> FindFoldRegions(string text)
    {
        var lines = SplitLines(text);
        var regions = new List<FoldRegion>();
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index];
            var trimmed = line.TrimEnd();
            if (trimmed.Length == 0 || !trimmed.EndsWith(':')) continue;
            if (trimmed.TrimStart().StartsWith('#')) continue;
            var indent = line.Length - line.TrimStart().Length;

            var end = index;
            for (var probe = index + 1; probe < lines.Length; probe++)
            {
                var candidate = lines[probe];
                if (candidate.Trim().Length == 0) continue; // 空行不终止区域，但也不延长它
                if (candidate.Length - candidate.TrimStart().Length <= indent) break;
                end = probe;
            }
            // 体只有一行时折叠没有意义：占位行本身也占一行，高度一点没省。
            if (end - index >= 2) regions.Add(new FoldRegion(index, end));
        }
        return regions;
    }

    /// <summary>找出包含指定行的最内层可折叠区域；没有则返回 null。</summary>
    public static FoldRegion? FindFoldRegionAt(string text, int line)
    {
        FoldRegion? best = null;
        foreach (var region in FindFoldRegions(text))
        {
            if (line < region.Header || line > region.End) continue;
            if (best is null || region.Header > best.Value.Header) best = region;
        }
        return best;
    }

    private static string[] SplitLines(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
}
