from datetime import datetime, timezone
from math import sqrt
from typing import Any


class RiskEngine:
    """
    Aggregates forensic findings from multiple analysis
    sources into a normalized investigation-priority score.

    The scoring model emphasizes:
        - High-confidence evidence
        - Specific indicators
        - Cross-source correlation
        - Diminishing returns for repeated findings

    This is an investigation-priority score, not a declaration
    that a system is malicious.
    """

    name = "risk"

    MAX_SCORE = 100

    # Base weights.
    #
    # High findings are intentionally strong.
    # Medium findings provide supporting evidence.
    # Low findings mainly provide contextual information.
    SEVERITY_WEIGHTS = {
        "high": 30,
        "medium": 5,
        "low": 1,
    }

    # Maximum contribution from each severity class.
    #
    # This prevents a large number of repetitive findings
    # from dominating the investigation score.
    SEVERITY_CAPS = {
        "high": 70,
        "medium": 25,
        "low": 10,
    }

    def analyze(
        self,
        analysis_results: dict[str, Any],
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        if correlations is None:
            correlations = []

        findings = self._collect_findings(
            analysis_results
        )

        severity_counts = {
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "low",
                )
            ).lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate severity contribution.
        severity_breakdown = (
            self._calculate_severity_breakdown(
                severity_counts
            )
        )

        severity_score = sum(
            severity_breakdown.values()
        )

        # Correlation provides additional confidence
        # when independent forensic sources agree.
        correlation_bonus = (
            self._correlation_bonus(
                correlations
            )
        )

        # Additional cross-source confidence.
        cross_source_bonus = (
            self._cross_source_bonus(
                findings
            )
        )

        final_score = min(
            self.MAX_SCORE,
            severity_score
            + correlation_bonus
            + cross_source_bonus,
        )

        risk_level = self._risk_level(
            final_score
        )

        top_findings = self._rank_findings(
            findings
        )

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "engine": self.name,
            "status": "complete",

            "started_at": started_at,
            "finished_at": finished_at,

            "finding_count": len(
                findings
            ),

            "severity_counts": (
                severity_counts
            ),

            "severity_breakdown": (
                severity_breakdown
            ),

            "severity_score": severity_score,

            "correlation_bonus": (
                correlation_bonus
            ),

            "cross_source_bonus": (
                cross_source_bonus
            ),

            "risk_score": final_score,

            "risk_level": risk_level,

            "top_findings": top_findings,

            "sources": list(
                analysis_results.keys()
            ),

            "correlation_count": len(
                correlations
            ),
        }

    # ========================================================
    # Severity scoring
    # ========================================================

    def _calculate_severity_breakdown(
        self,
        severity_counts: dict[str, int],
    ) -> dict[str, int]:

        breakdown = {}

        for severity in (
            "high",
            "medium",
            "low",
        ):

            count = severity_counts.get(
                severity,
                0,
            )

            if count <= 0:
                breakdown[severity] = 0
                continue

            weight = self.SEVERITY_WEIGHTS[
                severity
            ]

            cap = self.SEVERITY_CAPS[
                severity
            ]

            # Diminishing returns.
            #
            # First finding contributes most.
            # Repeated findings contribute progressively less.
            raw_score = (
                weight * sqrt(count)
            )

            contribution = min(
                cap,
                raw_score,
            )

            breakdown[severity] = int(
                round(contribution)
            )

        return breakdown

    # ========================================================
    # Collect findings
    # ========================================================

    def _collect_findings(
        self,
        analysis_results: dict[str, Any],
    ) -> list[dict[str, Any]]:

        findings = []

        for source, result in (
            analysis_results.items()
        ):

            if not isinstance(
                result,
                dict,
            ):
                continue

            source_findings = result.get(
                "findings",
                [],
            )

            if not isinstance(
                source_findings,
                list,
            ):
                continue

            for finding in source_findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                normalized = dict(
                    finding
                )

                normalized.setdefault(
                    "source",
                    source,
                )

                findings.append(
                    normalized
                )

        return findings

    # ========================================================
    # Cross-source confidence
    # ========================================================

    def _cross_source_bonus(
        self,
        findings: list[dict[str, Any]],
    ) -> int:

        """
        Adds a small bonus when findings originate from
        multiple independent forensic sources.

        Example:

            processes + memory + IOC

        is stronger evidence than repeated findings
        from one analyzer alone.
        """

        sources = set()

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "low",
                )
            ).lower()

            # Only meaningful findings participate.
            if severity not in (
                "high",
                "medium",
            ):
                continue

            source = finding.get(
                "source"
            )

            if source:
                sources.add(
                    str(source)
                )

        # More independent sources increase confidence,
        # but the bonus is deliberately capped.
        if len(sources) <= 1:
            return 0

        return min(
            10,
            (len(sources) - 1) * 2,
        )

    # ========================================================
    # Rank findings
    # ========================================================

    def _rank_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        severity_order = {
            "high": 0,
            "medium": 1,
            "low": 2,
        }

        ranked = sorted(
            findings,
            key=lambda finding: (
                severity_order.get(
                    str(
                        finding.get(
                            "severity",
                            "low",
                        )
                    ).lower(),
                    3,
                ),
                finding.get(
                    "timestamp",
                    "",
                ),
            ),
        )

        return ranked[:10]

    # ========================================================
    # Correlation bonus
    # ========================================================

    def _correlation_bonus(
        self,
        correlations: list[Any],
    ) -> int:

        bonus = 0

        for correlation in correlations:

            if not isinstance(
                correlation,
                dict,
            ):
                continue

            status = correlation.get(
                "status"
            )

            if status not in (
                "success",
                "complete",
            ):
                continue

            correlated_count = (
                correlation.get("correlated_connection_count")
                or correlation.get("match_count")
                or correlation.get("overlap_count")
                or correlation.get("matched_count")
                or 0
            )

            if not isinstance(
                correlated_count,
                int,
            ):
                continue

            if correlated_count > 0:

                # Correlation is supporting evidence.
                bonus += min(
                    5,
                    correlated_count,
                )

        return min(
            10,
            bonus,
        )

    # ========================================================
    # Risk level
    # ========================================================

    def _risk_level(
        self,
        score: int,
    ) -> str:

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "NONE"
