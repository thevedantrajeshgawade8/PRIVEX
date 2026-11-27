/**
 * Explainable deterministic privacy risk scoring.
 * Never invents opaque predictions; computes and explains exact point contributions.
 */

import { ENTITY_META, ENTITY_TYPES } from "./detectors.js";

const RISK_WEIGHTS = Object.freeze({
  [ENTITY_TYPES.CREDIT_CARD]: 30,
  [ENTITY_TYPES.AADHAAR]: 30,
  [ENTITY_TYPES.PAN]: 25,
  [ENTITY_TYPES.PHONE]: 12,
  [ENTITY_TYPES.EMAIL]: 10,
  [ENTITY_TYPES.IPV4]: 6,
});

/**
 * Evaluates privacy risk level and transparent score breakdown from entity counts.
 * @param {{ total: number, byType: Record<string, number> }} counts
 * @returns {{ level: 'LOW' | 'MEDIUM' | 'HIGH', score: number, summary: string, factors: Array<string> }}
 */
export function assessPrivacyRisk(counts) {
  if (!counts || counts.total === 0) {
    return {
      level: "LOW",
      score: 0,
      summary: "No sensitive PII entities detected.",
      factors: ["0 sensitive entities (+0 pts)"],
    };
  }

  let score = 0;
  let activeCategories = 0;
  const factors = [];

  for (const [type, weight] of Object.entries(RISK_WEIGHTS)) {
    const count = counts.byType[type] || 0;
    if (count > 0) {
      activeCategories += 1;
      // Diminishing weight after first occurrence prevents minor entities from inflating arbitrarily
      const pts = weight + Math.min(count - 1, 5) * Math.ceil(weight * 0.4);
      score += pts;
      factors.push(`${count}× ${ENTITY_META[type].label} (+${pts} pts)`);
    }
  }

  if (activeCategories >= 3) {
    score += 12;
    factors.push(`Cross-entity correlation (${activeCategories} PII categories, +12 pts)`);
  }

  let level = "LOW";
  if (score >= 70) {
    level = "HIGH";
  } else if (score >= 30) {
    level = "MEDIUM";
  }

  const summary =
    level === "HIGH"
      ? `High exposure (${score} pts): financial or national ID entities present.`
      : level === "MEDIUM"
        ? `Moderate exposure (${score} pts): identifiable personal or tax attributes detected.`
        : `Low exposure (${score} pts): limited contact or network identifiers found.`;

  return { level, score, summary, factors };
}
