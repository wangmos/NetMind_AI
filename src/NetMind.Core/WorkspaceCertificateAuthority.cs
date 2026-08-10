using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace NetMind.Core;

public sealed record TlsInspectionState(string Thumbprint, bool Enabled, DateTimeOffset CreatedAt);

public sealed class WorkspaceCertificateAuthority : IDisposable
{
    private const int MaximumLeafCertificates = NetMindDefaults.CertificateCacheCapacity;
    private readonly string _directory;
    private readonly string _statePath;
    // _cacheGate 只保护缓存字典与淘汰顺序；密钥生成与签发放在按主机的独立锁内，
    // 不同主机可并行签发，避免页面突发新主机时握手在全局锁后排队导致浏览器超时断开。
    private readonly Dictionary<string, X509Certificate2> _leafCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _leafOrder = [];
    private readonly ConcurrentDictionary<string, object> _hostGates = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheGate = new();
    private readonly object _authorityGate = new();
    private X509Certificate2? _authorityCache;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public WorkspaceCertificateAuthority(string workspacePath)
    {
        var root = Path.GetFullPath(workspacePath);
        _directory = Path.GetFullPath(Path.Combine(root, "tls"));
        if (!_directory.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("TLS 证书目录不在当前工作区内。");
        Directory.CreateDirectory(_directory);
        _statePath = Path.Combine(_directory, "state.json");
    }

    public string PublicCertificatePath => Path.Combine(_directory, "netmind-ca.cer");

    public TlsInspectionState GetState()
    {
        if (!File.Exists(_statePath)) return new TlsInspectionState(string.Empty, false, default);
        try
        {
            var state = JsonSerializer.Deserialize<TlsInspectionState>(File.ReadAllText(_statePath), JsonOptions);
            return state ?? new TlsInspectionState(string.Empty, false, default);
        }
        catch (JsonException) { return new TlsInspectionState(string.Empty, false, default); }
    }

    public bool IsEnabledAndTrusted()
    {
        var state = GetState();
        return state.Enabled && !string.IsNullOrWhiteSpace(state.Thumbprint) && FindCertificate(StoreName.Root, state.Thumbprint, requirePrivateKey: false) is not null;
    }

    public TlsInspectionState EnableAndTrust()
    {
        var state = EnsureAuthority();
        using var authority = FindCertificate(StoreName.My, state.Thumbprint, requirePrivateKey: true)
                              ?? throw new InvalidOperationException("工作区 CA 私钥不可用。");
        if (FindCertificate(StoreName.Root, state.Thumbprint, requirePrivateKey: false) is null)
        {
            using var publicCertificate = X509CertificateLoader.LoadCertificate(authority.Export(X509ContentType.Cert));
            using var rootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            rootStore.Open(OpenFlags.ReadWrite);
            rootStore.Add(publicCertificate);
        }
        state = state with { Enabled = true };
        WriteState(state);
        return state;
    }

    public void DisableAndRemoveTrust()
    {
        var state = GetState();
        if (!string.IsNullOrWhiteSpace(state.Thumbprint)) RemoveFromStore(StoreName.Root, state.Thumbprint);
        WriteState(state with { Enabled = false });
        ClearLeafCacheAndAuthorityCache();
    }

    public X509Certificate2 GetServerCertificate(string host)
    {
        host = host.Trim().TrimEnd('.');
        if (host.Length is < 1 or > 253 || host.Any(char.IsControl)) throw new InvalidDataException("TLS 目标主机名无效。");
        lock (_cacheGate)
        {
            if (_leafCache.TryGetValue(host, out var cached)) return cached;
        }
        var hostGate = _hostGates.GetOrAdd(host, static _ => new object());
        lock (hostGate)
        {
            lock (_cacheGate)
            {
                if (_leafCache.TryGetValue(host, out var cached)) return cached;
            }
            var certificate = IssueLeafCertificate(host);
            lock (_cacheGate)
            {
                _leafCache[host] = certificate;
                _leafOrder.Add(host);
                while (_leafCache.Count > MaximumLeafCertificates)
                {
                    var oldest = _leafOrder[0];
                    _leafOrder.RemoveAt(0);
                    if (_leafCache.Remove(oldest, out var evicted)) evicted.Dispose();
                }
            }
            return certificate;
        }
    }

    private X509Certificate2 IssueLeafCertificate(string host)
    {
        var authority = GetAuthorityCertificate();
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={EscapeDistinguishedName(host)}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var address)) san.AddIpAddress(address);
        else san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var serial = RandomNumberGenerator.GetBytes(16);
        using var issued = request.Create(authority, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30), serial);
        using var certificateWithPrivateKey = issued.CopyWithPrivateKey(rsa);
        return X509CertificateLoader.LoadPkcs12(certificateWithPrivateKey.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>CA 证书内存缓存：避免每次签发叶子证书都在锁内打开 Windows 证书库做 I/O。</summary>
    private X509Certificate2 GetAuthorityCertificate()
    {
        lock (_authorityGate)
        {
            if (_authorityCache is not null) return _authorityCache;
            var state = EnsureAuthority();
            _authorityCache = FindCertificate(StoreName.My, state.Thumbprint, requirePrivateKey: true)
                              ?? throw new InvalidOperationException("工作区 CA 私钥不可用。");
            return _authorityCache;
        }
    }

    private void ClearLeafCacheAndAuthorityCache()
    {
        lock (_cacheGate)
        {
            foreach (var certificate in _leafCache.Values) certificate.Dispose();
            _leafCache.Clear();
            _leafOrder.Clear();
        }
        lock (_authorityGate)
        {
            _authorityCache?.Dispose();
            _authorityCache = null;
        }
    }

    public void DeleteAuthorityForTesting()
    {
        var state = GetState();
        if (!string.IsNullOrWhiteSpace(state.Thumbprint))
        {
            RemoveFromStore(StoreName.Root, state.Thumbprint);
            RemoveFromStore(StoreName.My, state.Thumbprint);
        }
        Dispose();
    }
    private TlsInspectionState EnsureAuthority()
    {
        var state = GetState();
        if (!string.IsNullOrWhiteSpace(state.Thumbprint) && FindCertificate(StoreName.My, state.Thumbprint, requirePrivateKey: true) is not null)
            return state;

        using var rsa = RSA.Create(3072);
        var workspaceTag = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_directory)))[..10];
        var request = new CertificateRequest($"CN=NetMind AI 本地解密 CA {workspaceTag}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
        using var persisted = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        using (var personalStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            personalStore.Open(OpenFlags.ReadWrite);
            personalStore.Add(persisted);
        }
        File.WriteAllBytes(PublicCertificatePath, persisted.Export(X509ContentType.Cert));
        state = new TlsInspectionState(persisted.Thumbprint, false, DateTimeOffset.UtcNow);
        WriteState(state);
        return state;
    }

    private void WriteState(TlsInspectionState state)
    {
        var temporary = _statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temporary, _statePath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static X509Certificate2? FindCertificate(StoreName storeName, string thumbprint, bool requirePrivateKey)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (var certificate in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false))
        {
            if (requirePrivateKey && !certificate.HasPrivateKey) { certificate.Dispose(); continue; }
            return certificate;
        }
        return null;
    }

    private static void RemoveFromStore(StoreName storeName, string thumbprint)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        foreach (var certificate in matches)
        {
            store.Remove(certificate);
            certificate.Dispose();
        }
    }

    private static string EscapeDistinguishedName(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace(",", "\\,", StringComparison.Ordinal).Replace("+", "\\+", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    public void Dispose()
    {
        ClearLeafCacheAndAuthorityCache();
        _hostGates.Clear();
    }
}
