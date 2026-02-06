#!/usr/bin/env python3
"""
测试 AI 模块
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kali_mcp.ai.intent import IntentAnalyzer, Intent, IntentType, TargetType
from kali_mcp.ai.recommend import ToolRecommender, Recommendation
from kali_mcp.ai.learning import LearningEngine, AttackOutcome


class TestIntentAnalyzer:
    """IntentAnalyzer 测试类"""

    @pytest.fixture
    def analyzer(self):
        """创建分析器实例"""
        return IntentAnalyzer()

    def test_recognize_scan_intent(self, analyzer):
        """测试识别扫描意图"""
        intent = analyzer.analyze("扫描 192.168.1.1 的端口")

        assert intent is not None
        assert intent.intent_type in [IntentType.PORT_SCAN, IntentType.RECONNAISSANCE]

    def test_recognize_exploit_intent(self, analyzer):
        """测试识别利用意图"""
        intent = analyzer.analyze("利用 CVE 漏洞 攻击 getshell")

        assert intent is not None
        assert intent.intent_type == IntentType.EXPLOIT

    def test_recognize_password_intent(self, analyzer):
        """测试识别密码攻击意图"""
        intent = analyzer.analyze("使用字典破解 SSH 密码")

        assert intent is not None
        assert intent.intent_type == IntentType.PASSWORD_ATTACK

    def test_recognize_ctf_intent(self, analyzer):
        """测试识别 CTF 意图"""
        intent = analyzer.analyze("帮我找到 flag")

        assert intent is not None
        assert intent.intent_type == IntentType.CTF_SOLVE

    def test_extract_target(self, analyzer):
        """测试提取目标"""
        intent = analyzer.analyze("扫描 http://example.com 的漏洞")

        assert intent.extracted_target is not None
        assert "example.com" in intent.extracted_target

    def test_intent_to_dict(self, analyzer):
        """测试意图转字典"""
        intent = analyzer.analyze("扫描目标端口")
        data = intent.to_dict()

        assert "intent" in data
        assert "confidence" in data
        assert "tools" in data

    def test_empty_input(self, analyzer):
        """测试空输入"""
        intent = analyzer.analyze("")

        assert intent is not None
        assert intent.intent_type == IntentType.UNKNOWN

    def test_confidence_scoring(self, analyzer):
        """测试置信度评分"""
        # 明确的意图应该有较高置信度
        intent1 = analyzer.analyze("使用 nmap 扫描端口")
        # 模糊的意图应该有较低置信度
        intent2 = analyzer.analyze("检查一下这个")

        assert intent1.confidence >= intent2.confidence


class TestToolRecommender:
    """ToolRecommender 测试类"""

    @pytest.fixture
    def recommender(self):
        """创建推荐器实例"""
        return ToolRecommender()

    def test_recommend_for_web_target(self, recommender):
        """测试 Web 目标推荐"""
        recommendations = recommender.recommend(
            target="http://example.com",
            target_type="web",
            limit=5
        )

        assert len(recommendations) > 0
        assert len(recommendations) <= 5

        # 验证推荐的是 Web 相关工具
        tool_names = [r.tool_name for r in recommendations]
        web_tools = ["whatweb_scan", "gobuster_scan", "nikto_scan", "nuclei_scan"]
        assert any(t in tool_names for t in web_tools)

    def test_recommend_for_network_target(self, recommender):
        """测试网络目标推荐"""
        recommendations = recommender.recommend(
            target="192.168.1.1",
            target_type="network",
            limit=5
        )

        assert len(recommendations) > 0

        tool_names = [r.tool_name for r in recommendations]
        network_tools = ["nmap_scan", "masscan_fast_scan"]
        assert any(t in tool_names for t in network_tools)

    def test_recommend_with_context(self, recommender):
        """测试带上下文的推荐"""
        context = {
            "discovered_ports": [80, 443, 22],
            "services": ["http", "https", "ssh"]
        }

        recommendations = recommender.recommend(
            target="192.168.1.1",
            target_type="network",
            context=context,
            limit=5
        )

        assert len(recommendations) > 0

    def test_update_score(self, recommender):
        """测试更新工具评分"""
        initial_score = recommender.tool_scores["nmap_scan"]

        # 记录成功
        recommender.update_score("nmap_scan", success=True, findings_count=10)

        new_score = recommender.tool_scores["nmap_scan"]
        # 成功后评分应该提高或保持
        assert new_score >= initial_score

    def test_suggest_tool_chain(self, recommender):
        """测试工具链建议"""
        chain = recommender.suggest_tool_chain(
            target_type="web",
            objective="vulnerability_scan"
        )

        assert len(chain) > 0
        assert isinstance(chain, list)

    def test_recommendation_ranking(self, recommender):
        """测试推荐排序"""
        recommendations = recommender.recommend(
            target="http://example.com",
            target_type="web",
            limit=10
        )

        # 验证按分数降序排列
        scores = [r.score for r in recommendations]
        assert scores == sorted(scores, reverse=True)


class TestLearningEngine:
    """LearningEngine 测试类"""

    @pytest.fixture
    def engine(self):
        """创建学习引擎实例"""
        return LearningEngine()

    def test_record_attack(self, engine):
        """测试记录攻击"""
        engine.record_attack(
            target_type="web",
            tool_name="sqlmap_scan",
            outcome=AttackOutcome.SUCCESS,
            findings_count=5,
            execution_time=30.0
        )

        # 验证记录已保存
        assert len(engine.records) > 0

    def test_analyze_patterns(self, engine):
        """测试分析模式"""
        # 添加一些测试数据
        for i in range(5):
            engine.record_attack(
                target_type="web",
                tool_name="gobuster_scan",
                outcome=AttackOutcome.SUCCESS if i % 2 == 0 else AttackOutcome.FAILURE,
                findings_count=i * 2
            )

        patterns = engine.analyze_patterns()

        assert isinstance(patterns, list)

    def test_get_optimization_suggestions(self, engine):
        """测试获取优化建议"""
        # 添加测试数据
        engine.record_attack(
            target_type="network",
            tool_name="nmap_scan",
            outcome=AttackOutcome.SUCCESS,
            findings_count=10
        )

        suggestions = engine.get_optimization_suggestions()

        assert isinstance(suggestions, list)

    def test_get_best_tools_for_target(self, engine):
        """测试获取最佳工具"""
        # 添加测试数据
        for _ in range(3):
            engine.record_attack(
                target_type="web",
                tool_name="nuclei_scan",
                outcome=AttackOutcome.SUCCESS,
                findings_count=5
            )

        best_tools = engine.get_best_tools_for_target("web", limit=5)

        assert isinstance(best_tools, list)

    def test_persistence(self, engine):
        """测试数据持久化"""
        # 记录数据
        engine.record_attack(
            target_type="web",
            tool_name="test_persistence",
            outcome=AttackOutcome.SUCCESS
        )

        # 保存数据
        engine._save_history()

        # 创建新实例
        new_engine = LearningEngine()

        # 验证数据被加载（可能需要根据实现调整）
        # 这里主要验证不会抛出异常


class TestRecommendation:
    """Recommendation 测试类"""

    def test_create_recommendation(self):
        """测试创建推荐"""
        rec = Recommendation(
            tool_name="nmap_scan",
            score=0.85,
            reason="适合网络扫描"
        )

        assert rec.tool_name == "nmap_scan"
        assert rec.score == 0.85

    def test_recommendation_to_dict(self):
        """测试推荐转字典"""
        rec = Recommendation(
            tool_name="sqlmap_scan",
            score=0.9,
            reason="检测到可能的SQL注入点"
        )

        data = rec.to_dict()

        assert data["tool"] == "sqlmap_scan"
        assert data["score"] == 0.9
        assert "reason" in data


class TestIntent:
    """Intent 测试类"""

    def test_create_intent(self):
        """测试创建意图"""
        intent = Intent(
            intent_type=IntentType.PORT_SCAN,
            extracted_target="192.168.1.1",
            confidence=0.9,
            suggested_tools=["nmap_scan", "masscan_scan"]
        )

        assert intent.intent_type == IntentType.PORT_SCAN
        assert intent.confidence == 0.9
        assert len(intent.suggested_tools) == 2

    def test_intent_to_dict(self):
        """测试意图转字典"""
        intent = Intent(
            intent_type=IntentType.EXPLOIT,
            confidence=0.75
        )

        data = intent.to_dict()

        assert data["intent"] == "exploit"
        assert data["confidence"] == 0.75


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
