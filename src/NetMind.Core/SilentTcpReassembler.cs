namespace NetMind.Core;

/// <summary>
/// 单方向 TCP 字节流重组器：按序号排序衔接报文段，处理重传、重复与重叠；
/// 乱序缓冲超过上限时标记 <see cref="Broken"/>，调用方据此放弃正文解析。纯逻辑，不依赖驱动。
/// </summary>
public sealed class SilentTcpReassembler
{
    private readonly int _maximumBufferBytes;
    private readonly List<(uint Seq, byte[] Data)> _pending = [];
    private uint _expected;
    private bool _initialized;
    private int _bufferedBytes;

    public SilentTcpReassembler(int maximumBufferBytes = NetMindDefaults.SilentMaximumReassemblyBufferBytes)
    {
        _maximumBufferBytes = Math.Max(64 * 1024, maximumBufferBytes);
    }

    /// <summary>乱序缓冲超限后为真：该方向字节流不再可信。</summary>
    public bool Broken { get; private set; }

    /// <summary>已收到的最大序号末端，用于结算时判断数据量。</summary>
    public uint HighestSequence => _expected;

    /// <summary>以 SYN 序号初始化期望序号（SYN 占用一个序号位）。</summary>
    public void Initialize(uint synSequence)
    {
        _expected = synSequence + 1;
        _initialized = true;
    }

    /// <summary>喂入一段负载，返回本次新产生的连续有序字节（无新数据时为空数组）。</summary>
    public byte[] Append(uint sequence, ReadOnlySpan<byte> payload)
    {
        if (Broken || payload.IsEmpty) return [];
        // 未见 SYN（中途开始捕获）：首段数据即起点，不能像 SYN 那样额外消耗一个序号位，否则会吞掉首字节。
        if (!_initialized) { _expected = sequence; _initialized = true; }
        using var output = new MemoryStream();
        Accept(sequence, payload.ToArray(), output);
        DrainPending(output);
        return output.Length == 0 ? [] : output.ToArray();
    }

    private void Accept(uint sequence, byte[] data, MemoryStream output)
    {
        var end = sequence + (uint)data.Length;
        if (!SequenceLessThan(_expected, end)) return; // 已被完全覆盖的重传
        if (SequenceLessThan(sequence, _expected))
        {
            var skip = (int)(_expected - sequence);
            output.Write(data, skip, data.Length - skip);
            _expected = end;
            return;
        }
        if (sequence == _expected)
        {
            output.Write(data, 0, data.Length);
            _expected = end;
            return;
        }
        // 未来段：入有界乱序缓冲
        _bufferedBytes += data.Length;
        if (_bufferedBytes > _maximumBufferBytes)
        {
            Broken = true;
            _pending.Clear();
            _bufferedBytes = 0;
            return;
        }
        var index = _pending.FindIndex(item => !SequenceLessThan(item.Seq, sequence));
        _pending.Insert(index < 0 ? _pending.Count : index, (sequence, data));
    }

    private void DrainPending(MemoryStream output)
    {
        while (_pending.Count > 0 && Broken == false)
        {
            var (sequence, data) = _pending[0];
            if (SequenceLessThan(_expected, sequence)) break; // 仍有空洞
            _pending.RemoveAt(0);
            _bufferedBytes -= data.Length;
            Accept(sequence, data, output);
        }
    }

    /// <summary>TCP 序号回绕安全的比较：left 是否在 right 之前。</summary>
    private static bool SequenceLessThan(uint left, uint right) => (int)(left - right) < 0;
}
