namespace NetMind.Core;

/// <summary>
/// 流量批量操作的可见范围规则。隐藏行不能因为其在底层全集中位于两个序号之间而被范围勾选，
/// 也不能进入基于当前列表执行的保存、AI 或删除操作。
/// </summary>
public static class TrafficSelectionScope
{
    /// <summary>按当前显示顺序解析 Shift 范围；锚点已被筛掉时只返回目标行。</summary>
    public static Guid[] ResolveVisibleRange(IReadOnlyList<Guid> visibleIds, Guid? anchorId, Guid targetId)
    {
        var targetIndex = IndexOf(visibleIds, targetId);
        if (targetIndex < 0) return [];
        var anchorIndex = anchorId.HasValue ? IndexOf(visibleIds, anchorId.Value) : -1;
        if (anchorIndex < 0) return [targetId];
        var from = Math.Min(anchorIndex, targetIndex);
        var count = Math.Abs(anchorIndex - targetIndex) + 1;
        return visibleIds.Skip(from).Take(count).Distinct().ToArray();
    }

    /// <summary>把全局勾选集合裁剪为当前显示集合，并保持当前显示顺序。</summary>
    public static Guid[] IntersectVisibleChecked(IEnumerable<Guid> visibleIds, IReadOnlySet<Guid> checkedIds) =>
        visibleIds.Where(checkedIds.Contains).Distinct().ToArray();

    private static int IndexOf(IReadOnlyList<Guid> ids, Guid target)
    {
        for (var index = 0; index < ids.Count; index++)
            if (ids[index] == target) return index;
        return -1;
    }
}
