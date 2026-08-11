#!/usr/bin/env python3
"""soceng_dict.py — 社工字典生成器（爆破类升级 C1）。

输入 OSINT 信息（真实姓名/域名/公司/生日）→ 生成针对性密码字典。
比通用字典命中率高 10x+（姓名+年份/公司+@+数字/拼音+生日）。

用法:
    py soceng_dict.py --name "张三" --company "华为" --domain huawei.com -o out.txt
    py soceng_dict.py --name "Wang Wei" --email wangwei@corp.com --birthday 19900101
    py soceng_dict.py --names names.txt --companies comps.txt --domains domains.txt  # 批量
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
from pathlib import Path
from typing import List, Optional

# 中文拼音映射（常用姓/名）
SURNAMES = {
    "赵": "zhao", "钱": "qian", "孙": "sun", "李": "li", "周": "zhou", "吴": "wu",
    "郑": "zheng", "王": "wang", "冯": "feng", "陈": "chen", "褚": "chu", "卫": "wei",
    "蒋": "jiang", "沈": "shen", "韩": "han", "杨": "yang", "朱": "zhu", "秦": "qin",
    "尤": "you", "许": "xu", "何": "he", "吕": "lv", "施": "shi", "张": "zhang",
    "孔": "kong", "曹": "cao", "严": "yan", "华": "hua", "金": "jin", "魏": "wei",
    "陶": "tao", "姜": "jiang", "戚": "qi", "谢": "xie", "邹": "zou", "喻": "yu",
    "柏": "bai", "水": "shui", "窦": "dou", "章": "zhang", "云": "yun", "苏": "su",
    "潘": "pan", "葛": "ge", "奚": "xi", "范": "fan", "彭": "peng", "郎": "lang",
    "鲁": "lu", "韦": "wei", "昌": "chang", "马": "ma", "苗": "miao", "凤": "feng",
    "花": "hua", "方": "fang", "俞": "yu", "任": "ren", "袁": "yuan", "柳": "liu",
    "酆": "feng", "鲍": "bao", "史": "shi", "唐": "tang", "费": "fei", "廉": "lian",
    "岑": "cen", "薛": "xue", "雷": "lei", "贺": "he", "倪": "ni", "汤": "tang",
    "滕": "teng", "殷": "yin", "罗": "luo", "毕": "bi", "郝": "hao", "邬": "wu",
    "安": "an", "常": "chang", "乐": "le", "于": "yu", "时": "shi", "傅": "fu",
    "皮": "pi", "卞": "bian", "齐": "qi", "康": "kang", "伍": "wu", "余": "yu",
    "元": "yuan", "卜": "bu", "顾": "gu", "孟": "meng", "平": "ping", "黄": "huang",
    "和": "he", "穆": "mu", "萧": "xiao", "尹": "yin", "姚": "yao", "邵": "shao",
    "湛": "zhan", "汪": "wang", "祁": "qi", "毛": "mao", "禹": "yu", "狄": "di",
    "米": "mi", "贝": "bei", "明": "ming", "臧": "zang", "计": "ji", "伏": "fu",
    "成": "cheng", "戴": "dai", "谈": "tan", "宋": "song", "茅": "mao", "庞": "pang",
    "熊": "xiong", "纪": "ji", "舒": "shu", "屈": "qu", "项": "xiang", "祝": "zhu",
    "董": "dong", "梁": "liang", "杜": "du", "阮": "ruan", "蓝": "lan", "闵": "min",
    "席": "xi", "季": "ji", "麻": "ma", "强": "qiang", "贾": "jia", "路": "lu",
    "娄": "lou", "危": "wei", "江": "jiang", "童": "tong", "颜": "yan", "郭": "guo",
    "梅": "mei", "盛": "sheng", "林": "lin", "刁": "diao", "钟": "zhong", "徐": "xu",
    "邱": "qiu", "骆": "luo", "高": "gao", "夏": "xia", "蔡": "cai", "田": "tian",
    "樊": "fan", "胡": "hu", "凌": "ling", "霍": "huo", "虞": "yu", "万": "wan",
    "支": "zhi", "柯": "ke", "昝": "zan", "管": "guan", "卢": "lu", "莫": "mo",
    "经": "jing", "房": "fang", "裘": "qiu", "缪": "miao", "干": "gan", "解": "xie",
    "应": "ying", "宗": "zong", "丁": "ding", "宣": "xuan", "贲": "ben", "邓": "deng",
    "郁": "yu", "单": "shan", "杭": "hang", "洪": "hong", "包": "bao", "诸": "zhu",
    "左": "zuo", "石": "shi", "崔": "cui", "吉": "ji", "龚": "gong", "程": "cheng",
    "嵇": "ji", "邢": "xing", "裴": "pei", "陆": "lu", "荣": "rong", "翁": "weng",
    "荀": "xun", "羊": "yang", "於": "yu", "惠": "hui", "甄": "zhen", "曲": "qu",
    "家": "jia", "封": "feng", "芮": "rui", "羿": "yi", "储": "chu", "靳": "jin",
    "汲": "ji", "邴": "bing", "糜": "mi", "松": "song", "井": "jing", "段": "duan",
    "富": "fu", "巫": "wu", "乌": "wu", "焦": "jiao", "巴": "ba", "弓": "gong",
    "牧": "mu", "隗": "wei", "山": "shan", "谷": "gu", "车": "che", "侯": "hou",
    "宓": "mi", "蓬": "peng", "全": "quan", "郗": "xi", "班": "ban", "仰": "yang",
    "秋": "qiu", "仲": "zhong", "伊": "yi", "宫": "gong", "宁": "ning", "仇": "qiu",
    "栾": "luan", "暴": "bao", "甘": "gan", "钭": "tou", "厉": "li", "戎": "rong",
    "祖": "zu", "武": "wu", "符": "fu", "刘": "liu", "景": "jing", "詹": "zhan",
    "束": "shu", "龙": "long", "叶": "ye", "幸": "xing", "司": "si", "韶": "shao",
    "郜": "gao", "黎": "li", "蓟": "ji", "薄": "bo", "印": "yin", "宿": "su",
    "白": "bai", "怀": "huai", "蒲": "pu", "邰": "tai", "从": "cong", "鄂": "e",
    "索": "suo", "咸": "xian", "籍": "ji", "赖": "lai", "卓": "zhuo", "蔺": "lin",
    "屠": "tu", "蒙": "meng", "池": "chi", "乔": "qiao", "阴": "yin", "郁": "yu",
    "胥": "xu", "能": "neng", "苍": "cang", "双": "shuang", "闻": "wen", "莘": "shen",
    "党": "dang", "翟": "zhai", "谭": "tan", "贡": "gong", "劳": "lao", "逄": "pang",
    "姬": "ji", "申": "shen", "扶": "fu", "堵": "du", "冉": "ran", "宰": "zai",
    "郦": "li", "雍": "yong", "郤": "xi", "璩": "qu", "桑": "sang", "桂": "gui",
    "濮": "pu", "牛": "niu", "寿": "shou", "通": "tong", "边": "bian", "扈": "hu",
    "燕": "yan", "冀": "ji", "郏": "jia", "浦": "pu", "尚": "shang", "农": "nong",
    "温": "wen", "别": "bie", "庄": "zhuang", "晏": "yan", "柴": "chai", "瞿": "qu",
    "阎": "yan", "充": "chong", "慕": "mu", "连": "lian", "茹": "ru", "习": "xi",
    "宦": "huan", "艾": "ai", "鱼": "yu", "容": "rong", "向": "xiang", "古": "gu",
    "易": "yi", "慎": "shen", "戈": "ge", "廖": "liao", "庾": "yu", "终": "zhong",
    "暨": "ji", "居": "ju", "衡": "heng", "步": "bu", "都": "du", "耿": "geng",
    "满": "man", "弘": "hong", "匡": "kuang", "国": "guo", "文": "wen", "寇": "kou",
    "广": "guang", "禄": "lu", "阙": "que", "东": "dong", "欧": "ou", "殳": "shu",
    "沃": "wo", "利": "li", "蔚": "wei", "越": "yue", "夔": "kui", "隆": "long",
    "师": "shi", "巩": "gong", "厍": "she", "聂": "nie", "晁": "chao", "勾": "gou",
    "敖": "ao", "融": "rong", "冷": "leng", "訾": "zi", "辛": "xin", "阚": "kan",
    "那": "na", "简": "jian", "饶": "rao", "空": "kong", "曾": "zeng", "毋": "wu",
    "沙": "sha", "乜": "nie", "养": "yang", "鞠": "ju", "须": "xu", "丰": "feng",
    "巢": "chao", "关": "guan", "蒯": "kuai", "相": "xiang", "查": "zha", "后": "hou",
    "荆": "jing", "红": "hong", "游": "you", "竺": "zhu", "权": "quan", "逯": "lu",
    "盖": "gai", "益": "yi", "桓": "huan", "公": "gong", "万俟": "moqi", "司": "si",
    "上官": "shangguan", "欧阳": "ouyang", "夏侯": "xiahou", "诸葛": "zhuge",
    "闻人": "wenren", "东方": "dongfang", "赫连": "helian", "皇甫": "huangfu",
    "尉迟": "yuchi", "公羊": "gongyang", "澹台": "tantai", "公冶": "gongye",
    "宗政": "zongzheng", "濮阳": "puyang", "淳于": "chunyu", "单于": "chanyu",
    "太叔": "taishu", "申屠": "shentu", "公孙": "gongsun", "仲孙": "zhongsun",
    "轩辕": "xuanyuan", "令狐": "linghu", "钟离": "zhongli", "宇文": "yuwen",
    "长孙": "zhangsun", "慕容": "murong", "司徒": "situ", "司空": "sikong",
    "召": "shao", "有": "you", "舜": "shun", "叶赫那拉": "yehenala", "丛": "cong",
    "岳": "yue", "帅": "shuai", "缑": "gou", "亢": "kang", "况": "kuang", "后": "hou",
    "有": "you", "琴": "qin", "梁丘": "liangqiu", "左丘": "zuoqiu", "东门": "dongmen",
    "西门": "ximen", "商": "shang", "牟": "mou", "佘": "she", "佴": "nai", "伯": "bo",
    "赏": "shang", "南宫": "nangong", "墨": "mo", "哈": "ha", "谯": "qiao",
    "笪": "da", "年": "nian", "爱": "ai", "阳": "yang", "佟": "tong", "第五": "diwu",
    "言": "yan", "福": "fu",
}

# 常见名字单字拼音（高频）
COMMON_GIVEN = [
    "wei", "min", "juan", "yan", "fang", "jing", "lei", "li", "hong", "xiao",
    "yang", "jun", "qiang", "hua", "ping", "xia", "na", "qin", "chen", "lin",
    "liang", "fei", "dan", "wen", "chao", "tao", "peng", "yu", "jie", "hao",
    "gang", "wei", "bin", "shuai", "cong", "ning", "qing", "zhao", "kun",
    "shuang", "lu", "jie", "yan", "bo", "chun", "mei", "ling", "zhen",
    "xin", "ting", "shuang", "meng", "rui", "xiang", "ke", "si", "yu",
    "zhi", "wei", "an", "song", "yu", "chen", "jie", "ying", "xue",
    "lei", "dan", "hao", "jun", "hang", "yi", "cheng", "yi", "zhuo",
]

# 常见弱密码基础
BASE_PASS = [
    "123456", "12345678", "123456789", "1234567890", "123123", "111111",
    "888888", "666666", "000000", "5201314", "qwe123", "qweasd", "asd123",
    "abc123", "a123456", "Aa123456", "Admin123", "Password1", "P@ssw0rd",
    "admin123", "admin@123", "Admin@123", "admin888",
]


def parse_name(name: str) -> tuple:
    """解析姓名 → (姓, 名拼音) 列表。支持中文/英文。"""
    name = name.strip()
    if not name:
        return [], []
    # 英文名: "Wang Wei" → ["wang", "wei"]
    if re.search(r"[a-zA-Z]", name) and not re.search(r"[\u4e00-\u9fff]", name):
        parts = [p.lower() for p in re.split(r"[\s_\-\.]+", name) if p]
        return [], parts
    # 中文名
    surnames = []
    given = []
    for s, p in SURNAMES.items():
        if name.startswith(s):
            surnames.append(p)
            rest = name[len(s):]
            if rest:
                # 名拼音（简单映射：常用字查表，否则取首字母）
                given.append(rest)
    if not surnames:
        surnames = [name[0].lower()] if name else []
        given = [name[1:]] if len(name) > 1 else []
    return surnames, given


def pinyin_of_char(c: str) -> str:
    """单字拼音（常用字表，找不到返回空）。"""
    # 简化：常见名用字
    MAP = {
        "伟": "wei", "敏": "min", "娟": "juan", "燕": "yan", "芳": "fang",
        "静": "jing", "磊": "lei", "丽": "li", "红": "hong", "晓": "xiao",
        "阳": "yang", "军": "jun", "强": "qiang", "华": "hua", "平": "ping",
        "霞": "xia", "娜": "na", "琴": "qin", "晨": "chen", "琳": "lin",
        "亮": "liang", "飞": "fei", "丹": "dan", "文": "wen", "超": "chao",
        "涛": "tao", "鹏": "peng", "宇": "yu", "杰": "jie", "浩": "hao",
        "刚": "gang", "彬": "bin", "帅": "shuai", "聪": "cong", "宁": "ning",
        "青": "qing", "昭": "zhao", "坤": "kun", "双": "shuang", "璐": "lu",
        "洁": "jie", "波": "bo", "春": "chun", "梅": "mei", "玲": "ling",
        "珍": "zhen", "欣": "xin", "婷": "ting", "梦": "meng", "瑞": "rui",
        "祥": "xiang", "珂": "ke", "思": "si", "雨": "yu", "志": "zhi",
        "安": "an", "松": "song", "玉": "yu", "宸": "chen", "颖": "ying",
        "雪": "xue", "蕾": "lei", "丹": "dan", "皓": "hao", "骏": "jun",
        "航": "hang", "毅": "yi", "成": "cheng", "依": "yi", "卓": "zhuo",
        "泽": "ze", "涵": "han", "悦": "yue", "晴": "qing", "思": "si",
        "韵": "yun", "淑": "shu", "惠": "hui", "兰": "lan", "凤": "feng",
        "花": "hua", "香": "xiang", "艳": "yan", "秀": "xiu", "英": "ying",
        "莉": "li", "蓉": "rong", "珊": "shan", "芸": "yun", "菲": "fei",
    }
    return MAP.get(c, "")


def generate(name: str, company: str = "", domain: str = "",
              birthday: str = "", email: str = "") -> List[str]:
    """生成针对性密码字典。"""
    surnames, given = parse_name(name)
    cands: List[str] = []

    # 基础弱密码
    cands.extend(BASE_PASS)

    # 公司/域名词根
    roots = []
    if company:
        roots.append(company.lower())
    if domain:
        roots.append(domain.split(".")[0].lower())
    if email:
        local = email.split("@")[0]
        if local:
            roots.append(local)

    # 姓名拼音组合
    pinyins = []
    for s in surnames:
        pinyins.append(s)
    for g in given:
        g_py = "".join(pinyin_of_char(c) for c in g if pinyin_of_char(c))
        if g_py:
            pinyins.append(g_py)
    full_py = "".join(pinyins)
    initials = ""
    if len(pinyins) >= 2:
        full_py = pinyins[0] + pinyins[-1]  # 姓+名
    if full_py:
        cands.append(full_py)
        cands.append(full_py.capitalize())
        # 首字母
        if len(pinyins) >= 2:
            initials = pinyins[0][0] + pinyins[-1][0]
            cands.append(initials)

    # 姓名+年份
    years = ["2024", "2025", "2026", "2023", "2022", "2021", "2020", "1990", "1991",
             "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
             "2000", "2001", "2002", "2003", "2004", "2005", "1989", "1988",
             "1987", "1986", "1985", "1984", "1983", "1982", "1981", "1980"]
    for y in years:
        for base in [full_py, initials] if full_py else []:
            if base:
                cands.append(f"{base}{y}")
                cands.append(f"{base}@{y}")
                cands.append(f"{y}{base}")
        for r in roots:
            cands.append(f"{r}{y}")
            cands.append(f"{r}@{y}")
            cands.append(f"{r}{y}!")
            cands.append(f"{r}@{y}!")

    # 生日
    if birthday:
        b = birthday.replace("-", "").replace("/", "").replace(".", "")
        if len(b) >= 8:
            ymd = b[:8]
            cands.append(ymd)
            for base in [full_py, initials] if full_py else []:
                if base:
                    cands.append(f"{base}{ymd}")
                    cands.append(f"{base}@{ymd}")

    # 公司+@+数字
    for r in roots:
        cands.append(f"{r}@123")
        cands.append(f"{r}@1234")
        cands.append(f"{r}@123456")
        cands.append(f"{r}123")
        cands.append(f"{r}123456")
        cands.append(f"{r}888")
        cands.append(f"{r}666")

    # 去重 + 去空
    seen = set()
    out = []
    for c in cands:
        c = c.strip()
        if c and c not in seen and len(c) >= 6:
            seen.add(c)
            out.append(c)
    return out


def main():
    ap = argparse.ArgumentParser(description="社工字典生成器")
    ap.add_argument("--name", help="姓名 (张三 / Wang Wei)")
    ap.add_argument("--company", default="", help="公司名")
    ap.add_argument("--domain", default="", help="域名")
    ap.add_argument("--birthday", default="", help="生日 (YYYYMMDD)")
    ap.add_argument("--email", default="", help="邮箱")
    ap.add_argument("--names", help="姓名列表文件（每行一个）")
    ap.add_argument("--companies", help="公司列表文件")
    ap.add_argument("-o", "--output", default="/tmp/soceng_dict.txt", help="输出文件")
    args = ap.parse_args()

    all_pass = set()
    if args.name:
        all_pass.update(generate(args.name, args.company, args.domain, args.birthday, args.email))
    if args.names:
        names = [l.strip() for l in open(args.names, encoding="utf-8") if l.strip()]
        comps = []
        if args.companies:
            comps = [l.strip() for l in open(args.companies, encoding="utf-8") if l.strip()]
        for n in names:
            for c in (comps or [""]):
                all_pass.update(generate(n, c, args.domain, args.birthday, args.email))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sorted(all_pass)), encoding="utf-8")
    print(f"[soceng] 生成 {len(all_pass)} 个社工密码 → {out}")
    for p in sorted(all_pass)[:15]:
        print(f"  {p}")


if __name__ == "__main__":
    main()
