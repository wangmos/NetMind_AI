using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using NetMind.Core;

namespace NetMind.Workbench;

/// <summary>
/// JSON 树视图渲染器：将 <see cref="JsonTreeNode"/> 渲染到 WPF <see cref="TreeView"/>。
/// 节点行模板与深色样式全部定义在 App.xaml（资源键 <c>JsonTreeNodeTemplate</c> / <c>JsonTreeView</c>），
/// 本类只负责数据源接线与默认展开深度控制，内部不出现任何颜色字面量。
/// 树节点 <see cref="JsonTreeNode.Children"/> 为惰性属性，仅在对应行展开时由绑定触发实例化。
/// </summary>
internal static class JsonTreeViewRenderer
{
    /// <summary>App.xaml 中 JSON 节点行模板的资源键（阶段 E 集成时需要引用）。</summary>
    public const string TemplateResourceKey = "JsonTreeNodeTemplate";

    /// <summary>
    /// 渲染 JSON 树到目标 TreeView：设置行模板与数据源，并按
    /// <see cref="NetMindDefaults.JsonTreeDefaultExpandDepth"/> 展开前若干层。
    /// 渲染过程中任何异常都被捕获并降级为清空树视图，绝不向调用方抛出，避免界面崩溃；
    /// 调用方据此可通过“树是否为空”判断是否需要回退到扁平文本展示。
    /// </summary>
    public static void Render(TreeView host, JsonTreeNode root) => Render(host, root, NetMindDefaults.JsonTreeDefaultExpandDepth);

    /// <summary>渲染 JSON 树并显式指定默认展开深度（0 表示全部折叠，供大体积上下文按需逐层展开）。</summary>
    public static void Render(TreeView host, JsonTreeNode root, int expandDepth)
    {
        try
        {
            if (host is null || root is null)
            {
                // host 为 null 时 Clear 内部直接返回；root 为 null 时清空留空，由调用方回退。
                Clear(host!);
                return;
            }
            host.ItemTemplate = Application.Current.TryFindResource(TemplateResourceKey) as HierarchicalDataTemplate;
            // 根节点作为唯一顶层项（其本身可能是对象、数组或单个值，呈现逻辑一致）。
            host.ItemsSource = new[] { root };
            host.UpdateLayout();
            ExpandToDepth(host, expandDepth);
        }
        catch (Exception)
        {
            // 树视图属于只读展示增强：渲染失败即清空留空，由调用方回退既有文本路径，不得影响工作台主流程。
            try { Clear(host); } catch (Exception) { /* 宿主状态异常时同样静默，保持界面可用 */ }
        }
    }

    /// <summary>清空树视图（切换事务、视图降级或异常兜底时调用）。</summary>
    public static void Clear(TreeView host)
    {
        if (host is null) return;
        host.ItemsSource = null;
        host.ItemTemplate = null;
    }

    /// <summary>
    /// 按默认展开深度展开前若干层（深度 = 展开的层数：根节点为第 1 层）。
    /// 容器生成时机说明：设置 <see cref="TreeViewItem.IsExpanded"/> 后子容器要等惰性布局才生成，
    /// 因此每层展开后先 UpdateLayout 强制同步布局，再经 ItemContainerGenerator 下钻，保证多层展开生效；
    /// 未展开的分支其子容器与惰性 Children 均不会被实例化，首屏成本只覆盖默认展开范围。
    /// </summary>
    private static void ExpandToDepth(TreeView host, int depth)
    {
        if (depth <= 0) return;
        ExpandItems(host.ItemContainerGenerator, depth);
    }

    private static void ExpandItems(ItemContainerGenerator generator, int remainingDepth)
    {
        for (var index = 0; index < generator.Items.Count; index++)
        {
            if (generator.ContainerFromIndex(index) is not TreeViewItem item) continue;
            if (remainingDepth > 0)
            {
                item.IsExpanded = true;
                // 展开后子容器需同步布局才物化，先强制布局再向下展开下一层。
                item.UpdateLayout();
                ExpandItems(item.ItemContainerGenerator, remainingDepth - 1);
            }
        }
    }
}
