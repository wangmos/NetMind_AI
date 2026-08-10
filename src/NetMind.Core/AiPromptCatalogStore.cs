using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;

namespace NetMind.Core;

/// <summary>
/// 工作区 ai-prompts.json 承载的可编辑提示词目录：分析模板（内置可覆写、可新增自定义）
/// 与快捷追问列表（可增删改）。文件缺失或损坏时回退内置默认，不影响会话功能。
/// </summary>
public sealed record AiPromptCatalog(IReadOnlyList<AiPromptTemplate> Templates, IReadOnlyList<string> QuickFollowUps)
{
    /// <summary>默认快捷追问：与旧版界面内置按钮一致。</summary>
    public static readonly IReadOnlyList<string> DefaultQuickFollowUps =
    [
        "生成 Python 复现代码",
        "详解加密/签名流程",
        "分析潜在安全风险",
        "列出所有 API 参数和响应结构"
    ];

    public static AiPromptCatalog BuiltIn { get; } = new(AiPromptTemplate.All, DefaultQuickFollowUps);
}

public sealed class AiPromptCatalogStore
{
    public const string CatalogFileName = "ai-prompts.json";
    private const int MaximumDisplayNameChars = 60;
    private const int MaximumSystemPromptChars = 64_000;
    private const int MaximumRequirementChars = 8_000;
    private const int MaximumQuickFollowUps = 24;
    private const int MaximumQuickFollowUpChars = 500;
    private const long MaximumFileBytes = 2 * 1024 * 1024;

    // v1 内置模板曾被完整写入每个工作区。精确哈希只迁移“从未修改过的旧默认值”；
    // 用户实际编辑过的同名模板哈希不同，仍作为工作区覆盖保留。
    private static readonly IReadOnlyDictionary<string, string> LegacyBuiltInV1Hashes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["auto"] = "B7B246ED142C2E81957C2E000F40AB96E5DD6834206BC69918945E285D30189B",
            ["api-reverse"] = "0CDEB7AF26CE1E3BBDD4027225FB804F6235220CA34D70E29E6CF60A60439C19",
            ["security-audit"] = "E0B33B056514448342D9B231A2279D0715B18CD82735EFF6EECDD8F8F92FFD89",
            ["js-crypto"] = "ECA547FB6984C6753523F41C0DF550A99BCDBAE426F947A22E381AA72D0C2062",
            ["performance"] = "9EB108A90B5C0540F55D8D6F929AE931DCF36C7F017098AC035A9BFAF1805161"
        };

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    private readonly string _path;

    public AiPromptCatalogStore(string workspacePath)
    {
        var workspaceRoot = Path.GetFullPath(workspacePath);
        _path = Path.GetFullPath(Path.Combine(workspaceRoot, CatalogFileName));
        if (!_path.StartsWith(workspaceRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("提示词目录不在当前工作区内。");
        Directory.CreateDirectory(workspaceRoot);
    }

    /// <summary>读取目录：文件缺失/损坏回退内置默认；自定义模板与内置模板合并，同名 Id 以文件为准。</summary>
    public async Task<AiPromptCatalog> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path) || new FileInfo(_path).Length > MaximumFileBytes) return AiPromptCatalog.BuiltIn;
        try
        {
            await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var saved = await JsonSerializer.DeserializeAsync<SavedCatalog>(stream, JsonOptions, cancellationToken);
            if (saved is null) return AiPromptCatalog.BuiltIn;
            var templates = new List<AiPromptTemplate>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var template in saved.Templates ?? [])
            {
                var candidate = new AiPromptTemplate(template.Id, template.DisplayName, template.SystemPrompt, template.AnalysisRequirement);
                if (TryValidateTemplate(candidate, out var valid))
                {
                    if (LegacyBuiltInV1Hashes.TryGetValue(valid!.Id, out var legacyHash) &&
                        string.Equals(ComputeTemplateHash(valid), legacyHash, StringComparison.OrdinalIgnoreCase))
                        valid = AiPromptTemplate.Get(valid.Id);
                    templates.Add(valid!);
                    seen.Add(valid!.Id);
                }
            }
            // 文件未覆盖的内置模板补回，保证内置能力不因旧文件缺失。
            foreach (var builtIn in AiPromptTemplate.All)
                if (!seen.Contains(builtIn.Id)) templates.Add(builtIn);
            var followUps = (saved.QuickFollowUps ?? [])
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item.Trim())
                .Where(item => item.Length <= MaximumQuickFollowUpChars)
                .Distinct(StringComparer.Ordinal)
                .Take(MaximumQuickFollowUps)
                .ToArray();
            if (templates.Count == 0) templates.AddRange(AiPromptTemplate.All);
            if (followUps.Length == 0) followUps = AiPromptCatalog.DefaultQuickFollowUps.ToArray();
            return new AiPromptCatalog(templates, followUps);
        }
        catch (JsonException) { return AiPromptCatalog.BuiltIn; }
        catch (IOException) { return AiPromptCatalog.BuiltIn; }
    }

    /// <summary>整体覆盖写入：先写临时文件再原子替换，避免半截文件。</summary>
    public async Task SaveAsync(AiPromptCatalog catalog, CancellationToken cancellationToken = default)
    {
        var templates = new List<AiPromptTemplate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var template in catalog.Templates)
        {
            if (!TryValidateTemplate(template, out var valid) || !seen.Add(valid!.Id)) continue;
            templates.Add(valid);
        }
        if (templates.Count == 0) throw new InvalidDataException("至少保留一个分析模板。");
        var followUps = catalog.QuickFollowUps
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Trim())
            .Where(item => item.Length <= MaximumQuickFollowUpChars)
            .Distinct(StringComparer.Ordinal)
            .Take(MaximumQuickFollowUps)
            .ToArray();
        var payload = new SavedCatalog
        {
            Templates = templates.Select(template => new SavedTemplate
            {
                Id = template.Id,
                DisplayName = template.DisplayName,
                SystemPrompt = template.SystemPrompt,
                AnalysisRequirement = template.AnalysisRequirement
            }).ToArray(),
            QuickFollowUps = followUps
        };
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        var tempPath = _path + ".tmp";
        await File.WriteAllTextAsync(tempPath, json, new UTF8Encoding(false), cancellationToken);
        File.Move(tempPath, _path, overwrite: true);
    }

    /// <summary>新建自定义模板 Id：custom- 前缀加随机 Guid，避免与内置 Id 冲突。</summary>
    public static string NewCustomTemplateId() => "custom-" + Guid.NewGuid().ToString("N");

    private static string ComputeTemplateHash(AiPromptTemplate template)
    {
        var canonical = template.DisplayName + "\n" + template.SystemPrompt + "\n" + template.AnalysisRequirement;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static bool TryValidateTemplate(AiPromptTemplate? template, out AiPromptTemplate? valid)
    {
        valid = null;
        if (template is null) return false;
        var id = template.Id?.Trim() ?? string.Empty;
        var displayName = template.DisplayName?.Trim() ?? string.Empty;
        var systemPrompt = template.SystemPrompt ?? string.Empty;
        var requirement = template.AnalysisRequirement?.Trim() ?? string.Empty;
        if (id.Length is < 1 or > 64 || displayName.Length is < 1 or > MaximumDisplayNameChars) return false;
        if (systemPrompt.Length is < 1 or > MaximumSystemPromptChars || requirement.Length is < 1 or > MaximumRequirementChars) return false;
        valid = new AiPromptTemplate(id, displayName, systemPrompt, requirement);
        return true;
    }

    private sealed class SavedCatalog
    {
        public SavedTemplate[]? Templates { get; set; }
        public string[]? QuickFollowUps { get; set; }
    }

    private sealed class SavedTemplate
    {
        public string Id { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string SystemPrompt { get; set; } = string.Empty;
        public string AnalysisRequirement { get; set; } = string.Empty;
    }
}
