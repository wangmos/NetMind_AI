# 百度搜索关键字固定为 888
#
# 用途：钩子脚本。在脚本页「设为采集钩子」→ 勾选挂载点「发送前」→ 勾选「启用请求钩子」→ 顶部「保存」。
#
# 匹配范围说明：规则按「搜索端点 + 带 wd 查询参数」命中，即 /s?...wd=...，这正是百度网页搜索的形态。
# 这里刻意不写 host 条件，好处是同一份脚本对 www.baidu.com、m.baidu.com 以及本地回环测试都成立；
# 若只想作用于百度，给规则再加一条 'host': r'(^|\.)baidu\.com$' 即可（条件之间是 AND）。
#
# 未命中的流量完全不受影响：只有命中的请求才会阻塞等待裁决，其余仍是即发即忘。

INTERCEPT = [
    {
        'event': 'request.before_send',
        'method': r'^GET$',
        'endpoint': r'^/s\?',
        'url': r'[?&](?:wd|word)=',
    },
]

# 固定后的搜索词。只用 ASCII 数字，无需再做百分号编码。
FIXED_KEYWORD = '888'

# 百度网页搜索的关键字参数：wd 是主参数，word 在部分入口上等价。
KEYWORD_PARAMETERS = ('wd', 'word')


def _rewrite_query(query):
    """把查询串里的关键字参数替换为固定值，其余参数原样保留。返回 (新查询串, 是否改动)。"""
    rewritten = []
    changed = False
    for pair in query.split('&'):
        name, separator, value = pair.partition('=')
        if separator and name in KEYWORD_PARAMETERS:
            if value != FIXED_KEYWORD:
                changed = True
            rewritten.append(name + '=' + FIXED_KEYWORD)
        else:
            rewritten.append(pair)
    return '&'.join(rewritten), changed


def on_before_send(event):
    """命中即改写：返回 dict 表示改写内容，返回 None 表示原样放行。"""
    url = event.get('url') or ''
    prefix, separator, query = url.partition('?')
    if not separator:
        return None

    new_query, changed = _rewrite_query(query)
    if not changed:
        # 关键字已经是 888，不必改写；返回 None 让请求原样放行。
        return None

    return {
        'url': prefix + '?' + new_query,
        # finding 会经采集后台以 hooks.finding 审计事件落盘，便于事后核对改写了哪些请求。
        'finding': {
            'note': '百度搜索关键字已固定为 ' + FIXED_KEYWORD,
            'originalUrl': url,
        },
    }
