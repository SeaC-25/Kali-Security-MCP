"""
机器学习驱动的策略优化引擎
===========================

基于实际测试结果的学习：
- 测试结果记录和分析
- Payload有效性评估
- 目标指纹相似度匹配
- 策略权重动态调整
"""

import json
import logging
import os
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import math

logger = logging.getLogger(__name__)


class LearningEngine:
    """
    基于实际结果的学习引擎

    功能：
    - 记录测试结果
    - 计算Payload有效性
    - 基于历史数据推荐Payload
    - 目标指纹相似度分析
    - 策略权重动态更新
    """

    def __init__(self, data_path: str = "~/.kali_mcp_learning"):
        """
        初始化学习引擎

        Args:
            data_path: 学习数据存储路径
        """
        self.data_path = Path(data_path).expanduser()
        self.data_path.mkdir(parents=True, exist_ok=True)

        # 数据文件
        self.history_file = self.data_path / "test_history.json"
        self.effectiveness_file = self.data_path / "payload_effectiveness.json"
        self.fingerprints_file = self.data_path / "target_fingerprints.json"
        self.strategies_file = self.data_path / "strategy_weights.json"

        # 内存数据
        self.test_history: List[Dict] = []
        self.payload_effectiveness: Dict[str, Dict] = {}
        self.target_fingerprints: Dict[str, Dict] = {}
        self.strategy_weights: Dict[str, float] = {}

        # 统计
        self.stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'payloads_analyzed': 0,
            'targets_profiled': 0
        }

        # 加载历史数据
        self._load_data()

    def _load_data(self):
        """加载历史学习数据"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    self.test_history = json.load(f)
                    self.stats['total_tests'] = len(self.test_history)

            if self.effectiveness_file.exists():
                with open(self.effectiveness_file, 'r') as f:
                    self.payload_effectiveness = json.load(f)
                    self.stats['payloads_analyzed'] = len(self.payload_effectiveness)

            if self.fingerprints_file.exists():
                with open(self.fingerprints_file, 'r') as f:
                    self.target_fingerprints = json.load(f)
                    self.stats['targets_profiled'] = len(self.target_fingerprints)

            if self.strategies_file.exists():
                with open(self.strategies_file, 'r') as f:
                    self.strategy_weights = json.load(f)

            logger.info(f"[Learning] 加载历史数据: {self.stats}")

        except Exception as e:
            logger.error(f"[Learning] 加载数据失败: {e}")

    def _save_data(self):
        """保存学习数据"""
        try:
            with open(self.history_file, 'w') as f:
                # 只保存最近10000条记录
                json.dump(self.test_history[-10000:], f, indent=2)

            with open(self.effectiveness_file, 'w') as f:
                json.dump(self.payload_effectiveness, f, indent=2)

            with open(self.fingerprints_file, 'w') as f:
                json.dump(self.target_fingerprints, f, indent=2)

            with open(self.strategies_file, 'w') as f:
                json.dump(self.strategy_weights, f, indent=2)

        except Exception as e:
            logger.error(f"[Learning] 保存数据失败: {e}")

    def record_test(
        self,
        target_fingerprint: Dict[str, Any],
        test_type: str,
        payload_used: str,
        response_features: Dict[str, Any],
        success: bool,
        extracted_data: Any = None,
        confidence: float = 0.5
    ):
        """
        记录测试结果

        Args:
            target_fingerprint: 目标特征指纹
            test_type: 测试类型 (sql_injection, xss, lfi, etc.)
            payload_used: 使用的Payload
            response_features: 响应特征
            success: 是否成功
            extracted_data: 提取的数据
            confidence: 置信度
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "target_fingerprint": target_fingerprint,
            "test_type": test_type,
            "payload": payload_used,
            "payload_hash": self._hash_payload(payload_used),
            "response_features": response_features,
            "success": success,
            "extracted_data": extracted_data,
            "confidence": confidence
        }

        self.test_history.append(entry)
        self.stats['total_tests'] += 1
        if success:
            self.stats['successful_tests'] += 1

        # 更新Payload有效性
        self._update_payload_effectiveness(entry)

        # 更新目标指纹库
        self._update_target_fingerprint(target_fingerprint, entry)

        # 定期保存
        if self.stats['total_tests'] % 100 == 0:
            self._save_data()

        logger.debug(f"[Learning] 记录测试: {test_type} - {'成功' if success else '失败'}")

    def _hash_payload(self, payload: str) -> str:
        """生成Payload哈希"""
        return hashlib.md5(payload.encode()).hexdigest()[:12]

    def _update_payload_effectiveness(self, entry: Dict):
        """更新Payload有效性统计"""
        payload_hash = entry['payload_hash']
        test_type = entry['test_type']
        key = f"{test_type}:{payload_hash}"

        if key not in self.payload_effectiveness:
            self.payload_effectiveness[key] = {
                'payload': entry['payload'],
                'test_type': test_type,
                'total_uses': 0,
                'successes': 0,
                'effectiveness': 0.0,
                'target_types': defaultdict(int),
                'first_seen': entry['timestamp'],
                'last_seen': entry['timestamp']
            }

        stats = self.payload_effectiveness[key]
        stats['total_uses'] += 1
        stats['last_seen'] = entry['timestamp']

        if entry['success']:
            stats['successes'] += 1

        # 计算有效性分数 (考虑置信度)
        stats['effectiveness'] = (stats['successes'] / stats['total_uses']) * entry.get('confidence', 0.5)

        # 记录对哪类目标有效
        fp = entry.get('target_fingerprint', {})
        tech = fp.get('technology', 'unknown')
        if isinstance(stats['target_types'], defaultdict):
            stats['target_types'] = dict(stats['target_types'])
        if tech not in stats['target_types']:
            stats['target_types'][tech] = 0
        if entry['success']:
            stats['target_types'][tech] += 1

        self.stats['payloads_analyzed'] = len(self.payload_effectiveness)

    def _update_target_fingerprint(
        self,
        fingerprint: Dict[str, Any],
        entry: Dict
    ):
        """更新目标指纹库"""
        fp_hash = self._hash_fingerprint(fingerprint)

        if fp_hash not in self.target_fingerprints:
            self.target_fingerprints[fp_hash] = {
                'fingerprint': fingerprint,
                'tests_performed': [],
                'vulnerabilities_found': [],
                'first_seen': entry['timestamp'],
                'last_seen': entry['timestamp']
            }

        target = self.target_fingerprints[fp_hash]
        target['last_seen'] = entry['timestamp']
        target['tests_performed'].append({
            'test_type': entry['test_type'],
            'success': entry['success'],
            'timestamp': entry['timestamp']
        })

        if entry['success']:
            target['vulnerabilities_found'].append({
                'type': entry['test_type'],
                'payload': entry['payload'],
                'timestamp': entry['timestamp']
            })

        self.stats['targets_profiled'] = len(self.target_fingerprints)

    def _hash_fingerprint(self, fingerprint: Dict) -> str:
        """生成指纹哈希"""
        # 提取关键特征
        key_features = {
            'technology': fingerprint.get('technology', ''),
            'server': fingerprint.get('server', ''),
            'framework': fingerprint.get('framework', ''),
            'language': fingerprint.get('language', '')
        }
        fp_str = json.dumps(key_features, sort_keys=True)
        return hashlib.md5(fp_str.encode()).hexdigest()[:16]

    def get_recommended_payloads(
        self,
        test_type: str,
        target_fingerprint: Dict[str, Any],
        limit: int = 10
    ) -> List[Dict]:
        """
        基于历史数据推荐Payload

        Args:
            test_type: 测试类型
            target_fingerprint: 目标指纹
            limit: 返回数量限制

        Returns:
            List[Dict]: 推荐的Payload列表，按有效性排序
        """
        recommendations = []
        target_tech = target_fingerprint.get('technology', 'unknown')

        for key, stats in self.payload_effectiveness.items():
            if not key.startswith(f"{test_type}:"):
                continue

            # 计算综合评分
            score = self._calculate_payload_score(stats, target_fingerprint)

            recommendations.append({
                'payload': stats['payload'],
                'score': score,
                'total_uses': stats['total_uses'],
                'success_rate': stats['successes'] / max(stats['total_uses'], 1),
                'effectiveness': stats['effectiveness'],
                'works_on_tech': stats['target_types'].get(target_tech, 0) > 0
            })

        # 按评分排序
        recommendations.sort(key=lambda x: x['score'], reverse=True)

        return recommendations[:limit]

    def _calculate_payload_score(
        self,
        payload_stats: Dict,
        target_fingerprint: Dict
    ) -> float:
        """
        计算Payload综合评分

        考虑因素：
        - 历史有效性
        - 对类似目标的成功率
        - 使用频率（防止过拟合到少量成功）
        """
        base_score = payload_stats['effectiveness']

        # 使用频率加权
        uses = payload_stats['total_uses']
        if uses < 3:
            confidence_weight = 0.5  # 数据量少，降低置信度
        elif uses < 10:
            confidence_weight = 0.7
        else:
            confidence_weight = 1.0

        # 目标技术匹配加权
        target_tech = target_fingerprint.get('technology', 'unknown')
        tech_successes = payload_stats['target_types'].get(target_tech, 0)
        if tech_successes > 0:
            tech_weight = min(1.0 + (tech_successes * 0.1), 2.0)
        else:
            tech_weight = 1.0

        # 时间衰减（较新的结果权重更高）
        try:
            last_seen = datetime.fromisoformat(payload_stats['last_seen'])
            days_ago = (datetime.now() - last_seen).days
            time_weight = math.exp(-days_ago / 365)  # 年衰减
        except:
            time_weight = 0.5

        return base_score * confidence_weight * tech_weight * time_weight

    def get_attack_strategy(
        self,
        target_fingerprint: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        基于历史数据推荐攻击策略

        Args:
            target_fingerprint: 目标指纹

        Returns:
            Dict: 推荐的攻击策略
        """
        strategy = {
            'recommended_tests': [],
            'priority_order': [],
            'estimated_success_rates': {},
            'similar_targets_found': 0
        }

        # 查找相似目标
        similar_targets = self._find_similar_targets(target_fingerprint)
        strategy['similar_targets_found'] = len(similar_targets)

        # 分析相似目标的漏洞模式
        vuln_counts = defaultdict(int)
        for target in similar_targets:
            for vuln in target.get('vulnerabilities_found', []):
                vuln_counts[vuln['type']] += 1

        # 计算各测试类型的预期成功率
        test_types = ['sql_injection', 'xss', 'command_injection', 'lfi', 'auth_bypass']

        for test_type in test_types:
            # 基础成功率 (来自全局统计)
            type_tests = [t for t in self.test_history if t['test_type'] == test_type]
            if type_tests:
                base_rate = sum(1 for t in type_tests if t['success']) / len(type_tests)
            else:
                base_rate = 0.1

            # 相似目标成功率加权
            similar_rate = vuln_counts.get(test_type, 0) / max(len(similar_targets), 1)

            # 综合成功率
            estimated_rate = (base_rate * 0.3) + (similar_rate * 0.7) if similar_targets else base_rate

            strategy['estimated_success_rates'][test_type] = round(estimated_rate, 3)

        # 按预期成功率排序
        sorted_tests = sorted(
            strategy['estimated_success_rates'].items(),
            key=lambda x: x[1],
            reverse=True
        )

        strategy['priority_order'] = [t[0] for t in sorted_tests]
        strategy['recommended_tests'] = [
            {'type': t[0], 'estimated_success_rate': t[1]}
            for t in sorted_tests if t[1] > 0.05
        ]

        return strategy

    def _find_similar_targets(
        self,
        fingerprint: Dict[str, Any],
        threshold: float = 0.6
    ) -> List[Dict]:
        """查找相似的历史目标"""
        similar = []

        for fp_hash, target in self.target_fingerprints.items():
            similarity = self._calculate_fingerprint_similarity(
                fingerprint,
                target['fingerprint']
            )
            if similarity >= threshold:
                similar.append({
                    **target,
                    'similarity': similarity
                })

        # 按相似度排序
        similar.sort(key=lambda x: x['similarity'], reverse=True)
        return similar[:20]  # 最多返回20个

    def _calculate_fingerprint_similarity(
        self,
        fp1: Dict,
        fp2: Dict
    ) -> float:
        """
        计算两个指纹的相似度

        Returns:
            float: 0.0-1.0之间的相似度
        """
        features = ['technology', 'server', 'framework', 'language', 'os']
        matches = 0
        total = 0

        for feature in features:
            v1 = fp1.get(feature, '').lower()
            v2 = fp2.get(feature, '').lower()

            if v1 and v2:
                total += 1
                if v1 == v2:
                    matches += 1
                elif v1 in v2 or v2 in v1:
                    matches += 0.5

        return matches / max(total, 1)

    def update_strategy_weights(
        self,
        strategy_name: str,
        execution_result: Dict[str, Any]
    ):
        """
        根据执行结果更新策略权重

        Args:
            strategy_name: 策略名称
            execution_result: 执行结果
        """
        if strategy_name not in self.strategy_weights:
            self.strategy_weights[strategy_name] = 1.0

        current_weight = self.strategy_weights[strategy_name]

        # 根据结果调整权重
        success = execution_result.get('success', False)
        vulnerabilities_found = len(execution_result.get('vulnerabilities', []))
        time_taken = execution_result.get('elapsed_time', 0)

        # 成功奖励
        if success:
            current_weight *= 1.1

        # 发现漏洞额外奖励
        if vulnerabilities_found > 0:
            current_weight *= (1 + 0.05 * vulnerabilities_found)

        # 失败惩罚
        if not success:
            current_weight *= 0.95

        # 限制权重范围
        self.strategy_weights[strategy_name] = max(0.1, min(10.0, current_weight))

        self._save_data()

    def get_learning_summary(self) -> Dict[str, Any]:
        """获取学习统计摘要"""
        summary = {
            'statistics': self.stats.copy(),
            'top_effective_payloads': {},
            'most_vulnerable_tech': {},
            'strategy_weights': self.strategy_weights.copy()
        }

        # 各类型最有效的Payload
        for test_type in ['sql_injection', 'xss', 'command_injection', 'lfi']:
            type_payloads = [
                (k, v) for k, v in self.payload_effectiveness.items()
                if k.startswith(f"{test_type}:")
            ]
            type_payloads.sort(key=lambda x: x[1]['effectiveness'], reverse=True)

            summary['top_effective_payloads'][test_type] = [
                {
                    'payload': p[1]['payload'][:50] + '...' if len(p[1]['payload']) > 50 else p[1]['payload'],
                    'effectiveness': round(p[1]['effectiveness'], 3),
                    'uses': p[1]['total_uses']
                }
                for p in type_payloads[:3]
            ]

        # 统计各技术栈的漏洞发现率
        tech_vulns = defaultdict(lambda: {'total': 0, 'vulnerable': 0})
        for target in self.target_fingerprints.values():
            tech = target['fingerprint'].get('technology', 'unknown')
            tech_vulns[tech]['total'] += 1
            if target.get('vulnerabilities_found'):
                tech_vulns[tech]['vulnerable'] += 1

        for tech, counts in tech_vulns.items():
            if counts['total'] >= 3:  # 至少3个样本
                summary['most_vulnerable_tech'][tech] = {
                    'vulnerability_rate': round(counts['vulnerable'] / counts['total'], 3),
                    'sample_size': counts['total']
                }

        # 按漏洞率排序
        summary['most_vulnerable_tech'] = dict(
            sorted(
                summary['most_vulnerable_tech'].items(),
                key=lambda x: x[1]['vulnerability_rate'],
                reverse=True
            )[:10]
        )

        return summary

    def export_knowledge(self, output_file: str = None) -> Dict:
        """
        导出学习知识库

        Args:
            output_file: 输出文件路径

        Returns:
            Dict: 导出的知识数据
        """
        knowledge = {
            'exported_at': datetime.now().isoformat(),
            'statistics': self.stats,
            'payload_effectiveness': self.payload_effectiveness,
            'strategy_weights': self.strategy_weights,
            'target_fingerprint_count': len(self.target_fingerprints)
        }

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(knowledge, f, indent=2)
            logger.info(f"[Learning] 导出知识库到: {output_file}")

        return knowledge

    def import_knowledge(self, input_file: str):
        """
        导入学习知识库

        Args:
            input_file: 输入文件路径
        """
        try:
            with open(input_file, 'r') as f:
                knowledge = json.load(f)

            # 合并Payload有效性数据
            for key, value in knowledge.get('payload_effectiveness', {}).items():
                if key not in self.payload_effectiveness:
                    self.payload_effectiveness[key] = value
                else:
                    # 合并统计
                    existing = self.payload_effectiveness[key]
                    existing['total_uses'] += value['total_uses']
                    existing['successes'] += value['successes']
                    existing['effectiveness'] = existing['successes'] / max(existing['total_uses'], 1)

            # 合并策略权重
            for key, value in knowledge.get('strategy_weights', {}).items():
                if key not in self.strategy_weights:
                    self.strategy_weights[key] = value
                else:
                    # 平均权重
                    self.strategy_weights[key] = (self.strategy_weights[key] + value) / 2

            self._save_data()
            logger.info(f"[Learning] 导入知识库: {input_file}")

        except Exception as e:
            logger.error(f"[Learning] 导入失败: {e}")

    def clear_all_data(self):
        """清除所有学习数据"""
        self.test_history = []
        self.payload_effectiveness = {}
        self.target_fingerprints = {}
        self.strategy_weights = {}
        self.stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'payloads_analyzed': 0,
            'targets_profiled': 0
        }
        self._save_data()
        logger.info("[Learning] 已清除所有学习数据")
