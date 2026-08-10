using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// JSON 树节点种类（展示层分类，用于着色与折叠语义）。
/// </summary>
public enum JsonTreeNodeKind
{
    /// <summary>对象（{...}）。</summary>
    Object,

    /// <summary>数组（[...]）。</summary>
    Array,

    /// <summary>字符串值。</summary>
    String,

    /// <summary>数字值。</summary>
    Number,

    /// <summary>布尔值。</summary>
    Boolean,

    /// <summary>空值（null）。</summary>
    Null
}

/// <summary>
/// JSON 预览树节点（纯数据模型，零 WPF 依赖）。
/// 节点自持全部展示数据（解码后的字符串），不持有 <see cref="JsonElement"/> 引用；
/// 子节点列表惰性实例化：首次访问 <see cref="Children"/> 才构建，供树视图按需展开。
/// </summary>
public sealed class JsonTreeNode
{
    private static readonly IReadOnlyList<JsonTreeNode> EmptyChildren = Array.Empty<JsonTreeNode>();

    private readonly Snapshot _snapshot;
    private IReadOnlyList<JsonTreeNode>? _children;

    internal JsonTreeNode(Snapshot snapshot) => _snapshot = snapshot;

    /// <summary>节点种类。</summary>
    public JsonTreeNodeKind Kind => _snapshot.Kind;

    /// <summary>对象成员的键名（已解码）；数组元素与根节点为 null。</summary>
    public string? Key => _snapshot.Key;

    /// <summary>解码后的展示文本：叶子为值文本，容器为子项总数摘要，省略提示节点为中文文案。</summary>
    public string DisplayText => _snapshot.DisplayText;

    /// <summary>容器子项总数（真实计数，不含省略提示节点）；叶子为 0。</summary>
    public int ChildrenCount => _snapshot.ChildrenCount;

    /// <summary>是否为“其余 N 项已省略”提示节点。</summary>
    public bool IsEllipsis => _snapshot.IsEllipsis;

    /// <summary>是否为可折叠容器（对象或数组，省略提示节点不算容器）。</summary>
    public bool IsContainer => !IsEllipsis && Kind is JsonTreeNodeKind.Object or JsonTreeNodeKind.Array;

    /// <summary>
    /// 子节点列表：首次访问才实例化并缓存；叶子与省略提示节点返回空列表。
    /// 超出 <see cref="NetMindDefaults.JsonTreeMaximumChildrenPerNode"/> 的子项不会物化，
    /// 仅以 <see cref="IsEllipsis"/> 提示节点承载。
    /// </summary>
    public IReadOnlyList<JsonTreeNode> Children => _children ??=
        IsContainer && _snapshot.Children.Count > 0
            ? _snapshot.Children.Select(static child => new JsonTreeNode(child)).ToArray()
            : EmptyChildren;

    /// <summary>
    /// 节点数据内部快照：构建阶段从 <see cref="JsonElement"/> 抽取解码后的全部展示数据，
    /// 使树在 <see cref="JsonDocument"/> 释放后仍完全自持。
    /// </summary>
    internal sealed class Snapshot
    {
        public Snapshot(JsonTreeNodeKind kind, string? key, string displayText, int childrenCount,
            IReadOnlyList<Snapshot>? children = null, bool isEllipsis = false)
        {
            Kind = kind;
            Key = key;
            DisplayText = displayText;
            ChildrenCount = childrenCount;
            Children = children ?? Array.Empty<Snapshot>();
            IsEllipsis = isEllipsis;
        }

        public JsonTreeNodeKind Kind { get; }
        public string? Key { get; }
        public string DisplayText { get; }
        public int ChildrenCount { get; }
        public bool IsEllipsis { get; }
        public IReadOnlyList<Snapshot> Children { get; }
    }
}

/// <summary>
/// JSON 预览树静态构建器：只读展示用途，不影响存储、审计与复制链路。
/// 键名经 <see cref="JsonProperty.Name"/>、字符串值经 <see cref="JsonElement.GetString()"/> 天然完成 \uXXXX 解码。
/// </summary>
public static class JsonPreviewTreeBuilder
{
    /// <summary>尝试从正文构建 JSON 预览树；失败时返回 false 并给出中文降级原因。</summary>
    /// <param name="content">正文字节（调用方保证非 null）。</param>
    /// <param name="truncated">正文是否已被截断存储；截断正文不允许建树。</param>
    /// <param name="root">构建成功时输出的根节点。</param>
    /// <param name="reason">构建失败时的中文原因说明。</param>
    /// <param name="maxBytes">建树字节上限；默认取 <see cref="NetMindDefaults.JsonTreeMaximumBytes"/>，大体积 AI 上下文可显式放宽。</param>
    public static bool TryBuild(byte[] content, bool truncated, out JsonTreeNode? root, out string? reason)
        => TryBuild(content, truncated, out root, out reason, NetMindDefaults.JsonTreeMaximumBytes);

    /// <summary>同 <see cref="TryBuild(byte[], bool, out JsonTreeNode?, out string?)"/>，允许调用方显式指定建树字节上限。</summary>
    public static bool TryBuild(byte[] content, bool truncated, out JsonTreeNode? root, out string? reason, int maxBytes)
    {
        root = null;
        if (truncated)
        {
            reason = "正文已截断，无法构建 JSON 树。";
            return false;
        }
        if (content.Length > maxBytes)
        {
            reason = $"JSON 超过树视图大小上限（{maxBytes:N0} 字节），已降级为扁平文本展示。";
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(content);
        }
        catch (JsonException)
        {
            reason = "正文不是有效的 JSON，无法构建树。";
            return false;
        }

        // 树必须自持全部展示数据：构建完成即释放 JsonDocument，节点不保留任何 JsonElement 引用。
        using (document)
        {
            root = new JsonTreeNode(BuildSnapshot(document.RootElement, key: null, depth: 0));
        }
        reason = null;
        return true;
    }

    private static JsonTreeNode.Snapshot BuildSnapshot(JsonElement element, string? key, int depth)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var children = new List<JsonTreeNode.Snapshot>();
                var total = 0;
                foreach (var property in element.EnumerateObject())
                {
                    total++;
                    if (total <= NetMindDefaults.JsonTreeMaximumChildrenPerNode)
                        children.Add(BuildSnapshot(property.Value, property.Name, depth + 1));
                }
                AppendEllipsis(children, total);
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.Object, key, $"{total} 项", total, children);
            }
            case JsonValueKind.Array:
            {
                var children = new List<JsonTreeNode.Snapshot>();
                var total = 0;
                foreach (var item in element.EnumerateArray())
                {
                    total++;
                    if (total <= NetMindDefaults.JsonTreeMaximumChildrenPerNode)
                        children.Add(BuildSnapshot(item, key: null, depth + 1));
                }
                AppendEllipsis(children, total);
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.Array, key, $"{total} 项", total, children);
            }
            case JsonValueKind.String:
            {
                var value = element.GetString() ?? string.Empty;
                // 响应正文等字段以整串字符串携带 JSON：整串截断会吞掉长字段之后的兄弟字段，
                // 能解析为 JSON 时展开为子树，其中长值仍逐字段截断，与顶层展示语义一致。
                if (depth < NetMindDefaults.JsonPreviewMaximumEmbeddedJsonDepth)
                {
                    var embedded = TryBuildEmbeddedJsonSnapshot(value, key, depth);
                    if (embedded is not null) return embedded;
                }
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.String, key, JsonPreviewText.LimitDisplayValue(value), 0);
            }
            case JsonValueKind.Number:
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.Number, key, element.GetRawText(), 0);
            case JsonValueKind.True:
            case JsonValueKind.False:
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.Boolean, key, element.GetRawText(), 0);
            default:
                return new JsonTreeNode.Snapshot(JsonTreeNodeKind.Null, key, "null", 0);
        }
    }

    /// <summary>
    /// 尝试把字符串值解析为内嵌 JSON 并构建子树快照；不是合法 JSON（或非对象/数组）时返回 null，由调用方回退普通字符串截断。
    /// 子树构建完成后立即释放临时 JsonDocument，与顶层树一样完全自持。
    /// </summary>
    private static JsonTreeNode.Snapshot? TryBuildEmbeddedJsonSnapshot(string value, string? key, int depth)
    {
        if (value.Length is < 2 or > NetMindDefaults.JsonPreviewEmbeddedJsonMaximumCharacters) return null;
        var trimmed = value.AsSpan().TrimStart();
        if (trimmed.IsEmpty || (trimmed[0] != '{' && trimmed[0] != '[')) return null;
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(value);
        }
        catch (JsonException)
        {
            return null;
        }
        using (document)
        {
            if (document.RootElement.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return null;
            var inner = BuildSnapshot(document.RootElement, key: null, depth + 1);
            return new JsonTreeNode.Snapshot(inner.Kind, key, $"{inner.DisplayText} · 字符串内嵌 JSON", inner.ChildrenCount, inner.Children);
        }
    }

    /// <summary>容器子项超过实例化上限时，追加“其余 N 项已省略”提示节点（不改变真实总数）。</summary>
    private static void AppendEllipsis(List<JsonTreeNode.Snapshot> children, int total)
    {
        if (total <= NetMindDefaults.JsonTreeMaximumChildrenPerNode) return;
        children.Add(new JsonTreeNode.Snapshot(JsonTreeNodeKind.Null, null,
            $"其余 {total - NetMindDefaults.JsonTreeMaximumChildrenPerNode} 项已省略", 0, isEllipsis: true));
    }
}

/// <summary>
/// JSON 解码扁平文本构建器：逐元素遍历输出解码后的缩进纯文本
/// （不使用 <see cref="JsonSerializer"/>，避免非 ASCII 字符被重新转义为 \uXXXX），
/// 供树视图超限时的降级路径与无树场景复用。
/// </summary>
public static class JsonPreviewText
{
    private const int IndentWidth = 2;

    /// <summary>解析正文字节并输出解码后的缩进纯文本；解析失败时 <see cref="JsonException"/> 由调用方处理。</summary>
    public static string Build(byte[] content)
    {
        using var document = JsonDocument.Parse(content);
        return Build(document.RootElement);
    }

    /// <summary>从 <see cref="JsonElement"/> 输出解码后的缩进纯文本；输出总量受预览上限保护。</summary>
    public static string Build(JsonElement root)
    {
        var builder = new StringBuilder();
        var overflow = false;
        Append(root, builder, depth: 0, ref overflow);
        return builder.ToString();
    }

    /// <summary>单值展示截断：超过 <see cref="NetMindDefaults.JsonPreviewMaximumValueCharacters"/> 时截断并追加中文省略标记。</summary>
    internal static string LimitDisplayValue(string value) =>
        value.Length <= NetMindDefaults.JsonPreviewMaximumValueCharacters
            ? value
            : value[..NetMindDefaults.JsonPreviewMaximumValueCharacters] + $"…（共 {value.Length:N0} 字符，已截断）";

    private static void Append(JsonElement element, StringBuilder builder, int depth, ref bool overflow)
    {
        if (overflow) return;
        if (builder.Length > NetMindDefaults.BlobPreviewDefaultBytes)
        {
            overflow = true;
            builder.AppendLine().Append($"[扁平文本输出已达 {NetMindDefaults.BlobPreviewDefaultBytes:N0} 字符上限，停止继续输出]");
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                builder.Append('{');
                var first = true;
                foreach (var property in element.EnumerateObject())
                {
                    if (!first) builder.Append(',');
                    if (overflow) return;
                    builder.AppendLine();
                    AppendIndent(builder, depth + 1);
                    builder.Append('"').Append(property.Name).Append("\": ");
                    Append(property.Value, builder, depth + 1, ref overflow);
                    first = false;
                }
                if (!first)
                {
                    builder.AppendLine();
                    AppendIndent(builder, depth);
                }
                builder.Append('}');
                break;
            }
            case JsonValueKind.Array:
            {
                builder.Append('[');
                var first = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!first) builder.Append(',');
                    if (overflow) return;
                    builder.AppendLine();
                    AppendIndent(builder, depth + 1);
                    Append(item, builder, depth + 1, ref overflow);
                    first = false;
                }
                if (!first)
                {
                    builder.AppendLine();
                    AppendIndent(builder, depth);
                }
                builder.Append(']');
                break;
            }
            case JsonValueKind.String:
                builder.Append('"').Append(LimitDisplayValue(element.GetString() ?? string.Empty)).Append('"');
                break;
            default:
                // Number / true / false / null 的原始文本不含转义，可直接输出。
                builder.Append(element.GetRawText());
                break;
        }
    }

    private static void AppendIndent(StringBuilder builder, int depth) => builder.Append(' ', depth * IndentWidth);
}
