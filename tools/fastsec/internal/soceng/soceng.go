// Package soceng: social-engineering password dictionary generator.
package soceng

import (
	"fmt"
	"strings"
)

// 常见姓氏拼音（高频 Top 100）
var surnames = map[string]string{
	"李": "li", "王": "wang", "张": "zhang", "刘": "liu", "陈": "chen",
	"杨": "yang", "赵": "zhao", "黄": "huang", "周": "zhou", "吴": "wu",
	"徐": "xu", "孙": "sun", "胡": "hu", "朱": "zhu", "高": "gao",
	"林": "lin", "何": "he", "郭": "guo", "马": "ma", "罗": "luo",
	"梁": "liang", "宋": "song", "郑": "zheng", "谢": "xie", "韩": "han",
	"唐": "tang", "冯": "feng", "于": "yu", "董": "dong", "萧": "xiao",
	"程": "cheng", "曹": "cao", "袁": "yuan", "邓": "deng", "许": "xu",
	"傅": "fu", "沈": "shen", "曾": "zeng", "彭": "peng", "吕": "lv",
	"苏": "su", "卢": "lu", "蒋": "jiang", "蔡": "cai", "贾": "jia",
	"丁": "ding", "魏": "wei", "薛": "xue", "叶": "ye", "阎": "yan",
	"余": "yu", "潘": "pan", "杜": "du", "戴": "dai", "夏": "xia",
	"钟": "zhong", "汪": "wang", "田": "tian", "任": "ren", "姜": "jiang",
	"范": "fan", "方": "fang", "石": "shi", "姚": "yao", "谭": "tan",
	"廖": "liao", "邹": "zou", "熊": "xiong", "金": "jin", "陆": "lu",
	"郝": "hao", "孔": "kong", "白": "bai", "崔": "cui", "康": "kang",
	"毛": "mao", "邱": "qiu", "秦": "qin", "江": "jiang", "史": "shi",
	"顾": "gu", "侯": "hou", "邵": "shao", "孟": "meng", "龙": "long",
	"万": "wan", "段": "duan", "漕": "cao", "钱": "qian", "汤": "tang",
	"尹": "yin", "黎": "li", "易": "yi", "常": "chang", "武": "wu",
	"乔": "qiao", "贺": "he", "赖": "lai", "龚": "gong", "文": "wen",
}

// 常见名用字拼音
var givenMap = map[string]string{
	"伟": "wei", "敏": "min", "静": "jing", "磊": "lei", "军": "jun",
	"洋": "yang", "勇": "yong", "艳": "yan", "杰": "jie", "娟": "juan",
	"涛": "tao", "明": "ming", "超": "chao", "秀": "xiu", "霞": "xia",
	"平": "ping", "刚": "gang", "桂": "gui", "英": "ying", "华": "hua",
	"玉": "yu", "梅": "mei", "文": "wen", "辉": "hui", "强": "qiang",
	"健": "jian", "山": "shan", "波": "bo", "斌": "bin", "芳": "fang",
	"龙": "long", "丽": "li", "娜": "na", "玲": "ling", "燕": "yan",
	"鑫": "xin", "鹏": "peng", "宇": "yu", "浩": "hao", "飞": "fei",
}

// Generate: 生成社工字典
func Generate(name, company, domain, birthday, email string) []string {
	cands := map[string]bool{}

	// 基础弱密码
	base := []string{"123456", "12345678", "123456789", "123123", "111111",
		"888888", "666666", "5201314", "qwe123", "abc123", "a123456",
		"Aa123456", "Admin123", "P@ssw0rd", "admin123", "admin@123"}
	for _, b := range base {
		cands[b] = true
	}

	// 姓名拼音
	var pinyins []string
	runes := []rune(name)
	if len(runes) >= 2 {
		if py, ok := surnames[string(runes[0])]; ok {
			pinyins = append(pinyins, py)
		}
		// 名
		var givenPy []string
		for _, r := range runes[1:] {
			if py, ok := givenMap[string(r)]; ok {
				givenPy = append(givenPy, py)
			}
		}
		if len(givenPy) > 0 {
			pinyins = append(pinyins, givenPy...)
		}
	}
	var fullPy string
	var initials string
	if len(pinyins) >= 2 {
		fullPy = pinyins[0] + pinyins[1]
		initials = string(pinyins[0][0]) + string(pinyins[1][0])
	}
	if fullPy != "" {
		cands[fullPy] = true
		cands[strings.ToUpper(fullPy[:1])+fullPy[1:]] = true
	}
	if initials != "" {
		cands[initials] = true
	}

	// 词根（公司/域名/邮箱）
	var roots []string
	if company != "" {
		roots = append(roots, strings.ToLower(company))
	}
	if domain != "" {
		roots = append(roots, strings.Split(domain, ".")[0])
	}
	if email != "" {
		if local := strings.Split(email, "@")[0]; local != "" {
			roots = append(roots, strings.ToLower(local))
		}
	}

	// 姓名/词根 + 年份
	years := []string{"2024", "2025", "2026", "2023", "2022", "2020", "1990", "1995", "2000"}
	for _, y := range years {
		for _, base2 := range []string{fullPy, initials} {
			if base2 != "" {
				cands[base2+y] = true
				cands[base2+"@"+y] = true
			}
		}
		for _, r := range roots {
			cands[r+y] = true
			cands[r+"@"+y] = true
			cands[r+"@"+y+"!"] = true
		}
	}

	// 生日
	if len(birthday) >= 8 {
		ymd := strings.ReplaceAll(strings.ReplaceAll(birthday, "-", ""), "/", "")
		cands[ymd] = true
		for _, base2 := range []string{fullPy, initials} {
			if base2 != "" {
				cands[base2+ymd] = true
			}
		}
	}

	// 词根 + 数字
	for _, r := range roots {
		for _, suffix := range []string{"123", "1234", "123456", "888", "666"} {
			cands[r+suffix] = true
			cands[r+"@"+suffix] = true
		}
	}

	// 去重输出
	out := make([]string, 0, len(cands))
	for c := range cands {
		if len(c) >= 6 {
			out = append(out, c)
		}
	}
	return out
}

// Format: 渲染
func Format(passwords []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[soceng] %d passwords generated\n", len(passwords)))
	for i, p := range passwords {
		if i < 20 {
			sb.WriteString("  " + p + "\n")
		}
	}
	return sb.String()
}
