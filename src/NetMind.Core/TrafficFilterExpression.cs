namespace NetMind.Core;

/// <summary>
/// 流量搜索布尔表达式引擎：支持 &&（且）、||（或）、!（非）与 () 分组组合多个关键词，
/// 关键词本身仍为大小写不敏感的子串匹配；双引号可包裹含空格或特殊字符的词。
/// 不含运算符时行为与原单子串搜索完全一致；解析失败时回退为整串子串匹配，绝不向调用方抛出。
/// 优先级：! 高于 &&，&& 高于 ||。
/// </summary>
public static class TrafficFilterExpression
{
    /// <summary>把搜索框文本编译为"搜索文本是否命中"的谓词。</summary>
    public static Func<string, bool> Compile(string query)
    {
        query = query.Trim();
        if (query.Length == 0) return static _ => true;
        if (!ContainsOperators(query)) return Literal(query);
        try
        {
            var parser = new Parser(Tokenize(query));
            var predicate = parser.ParseOr();
            if (!parser.IsAtEnd) throw new FormatException("表达式存在无法解析的尾部记号。");
            return predicate;
        }
        catch (FormatException)
        {
            // 表达式不合法（如括号不配对、孤立运算符）时退回整串子串匹配，保证搜索永不失效。
            return Literal(query);
        }
    }

    private static Func<string, bool> Literal(string term) =>
        text => text.Contains(term, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsOperators(string query) =>
        query.Contains("&&", StringComparison.Ordinal) || query.Contains("||", StringComparison.Ordinal) ||
        query.Contains('(') || query.Contains(')') || query.Contains('!');

    private enum TokenKind { Term, And, Or, Not, LeftParen, RightParen }

    private readonly record struct Token(TokenKind Kind, string Text);

    /// <summary>词法切分：仅 && 与 || 是二元运算符（单个 &amp;/| 属于词内容，URL 中常见）。</summary>
    private static List<Token> Tokenize(string query)
    {
        var tokens = new List<Token>();
        var buffer = new System.Text.StringBuilder();

        void Flush()
        {
            var term = buffer.ToString().Trim();
            buffer.Clear();
            if (term.Length > 0) tokens.Add(new Token(TokenKind.Term, term));
        }

        for (var index = 0; index < query.Length; index++)
        {
            var current = query[index];
            if (current == '"' )
            {
                var closing = query.IndexOf('"', index + 1);
                if (closing < 0) throw new FormatException("双引号未闭合。");
                buffer.Append(query.AsSpan(index + 1, closing - index - 1));
                index = closing;
                continue;
            }
            if (current == '&' && index + 1 < query.Length && query[index + 1] == '&')
            {
                Flush();
                tokens.Add(new Token(TokenKind.And, "&&"));
                index++;
                continue;
            }
            if (current == '|' && index + 1 < query.Length && query[index + 1] == '|')
            {
                Flush();
                tokens.Add(new Token(TokenKind.Or, "||"));
                index++;
                continue;
            }
            switch (current)
            {
                case '!':
                    Flush();
                    tokens.Add(new Token(TokenKind.Not, "!"));
                    continue;
                case '(':
                    Flush();
                    tokens.Add(new Token(TokenKind.LeftParen, "("));
                    continue;
                case ')':
                    Flush();
                    tokens.Add(new Token(TokenKind.RightParen, ")"));
                    continue;
            }
            buffer.Append(current);
        }
        Flush();
        return tokens;
    }

    /// <summary>递归下降解析：or := and ('||' and)*；and := unary ('&amp;&amp;' unary)*；unary := '!' unary | '(' or ')' | term。</summary>
    private sealed class Parser(List<Token> tokens)
    {
        private int _position;

        public bool IsAtEnd => _position >= tokens.Count;

        private Token? Peek() => IsAtEnd ? null : tokens[_position];

        private Token Consume() => tokens[_position++];

        public Func<string, bool> ParseOr()
        {
            var branches = new List<Func<string, bool>> { ParseAnd() };
            while (Peek()?.Kind == TokenKind.Or)
            {
                Consume();
                branches.Add(ParseAnd());
            }
            return branches.Count == 1 ? branches[0] : text => branches.Any(branch => branch(text));
        }

        private Func<string, bool> ParseAnd()
        {
            var terms = new List<Func<string, bool>> { ParseUnary() };
            while (Peek()?.Kind == TokenKind.And)
            {
                Consume();
                terms.Add(ParseUnary());
            }
            return terms.Count == 1 ? terms[0] : text => terms.All(term => term(text));
        }

        private Func<string, bool> ParseUnary()
        {
            var token = Peek() ?? throw new FormatException("表达式意外结束。");
            switch (token.Kind)
            {
                case TokenKind.Not:
                    Consume();
                    var negated = ParseUnary();
                    return text => !negated(text);
                case TokenKind.LeftParen:
                    Consume();
                    var grouped = ParseOr();
                    if (Peek()?.Kind != TokenKind.RightParen) throw new FormatException("缺少右括号。");
                    Consume();
                    return grouped;
                case TokenKind.Term:
                    Consume();
                    return Literal(token.Text);
                default:
                    throw new FormatException($"记号 {token.Text} 位置非法。");
            }
        }
    }
}
