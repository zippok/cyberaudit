---
name: cyberaudit-ui-ux-a11y
description: "Executes all 10 UI/UX, Accessibility & Frontend Performance scanners: WCAG A11y Semantics, Responsive Touch Ergonomics, Color Contrast & Typography, Nielsen UX Heuristics, WCAG 2.2 Modern Compliance (Paste/Focus Obscured), Cognitive Ergonomics, Async UI States (Loading/Error/Empty/Double-Submit), Core Web Vitals (CLS/LCP/INP), Design System Token Drift & i18n, and Client Storage Token Exposure & SSR Hydration Safety. Executes 10 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, ui-ux-a11y, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit UI/UX Heuristics, WCAG 2.2 Accessibility & Core Web Vitals Skill (`cyberaudit-ui-ux-a11y`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`10` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- W3C WCAG 2.2 AA/AAA
- Nielsen Norman 10 Heuristics
- Google Core Web Vitals (LCP/CLS/INP)
- Laws of UX

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | WCAG 2.2 Modern Accessibility Compliance | Are inputs blocking paste or fixed elements obscuring focus? | Paste blocked on passwords, sticky headers hiding focus ring |
| 2 | Responsive Ergonomics & Touch Targets | Are tap targets at least 48x48px with no horizontal overflow? | Tiny icons, horizontal scrollbars on 375px mobile viewports |
| 3 | Color Contrast & Accessible Typography | Does text meet 4.5:1 (normal) or 3:1 (large) contrast ratios? | Low-contrast light gray text on white, hardcoded hex colors |
| 4 | Async UI States & Double-Submit Protection | Do forms handle loading, error, empty, and double-submit states? | Missing disabled button on submit, blocking window.alert() |
| 5 | Core Web Vitals (CLS, LCP, INP) | Are images dimensionless causing layout shifts or scroll listeners un-passive? | <img> without width/height, non-passive scroll listeners causing jank |
| 6 | Client Storage & SSR Hydration Safety | Are sensitive tokens stored in localStorage or non-deterministic SSR values rendered? | JWT in localStorage, Math.random() in SSR JSX causing hydration mismatch |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Hidden or decorative elements with aria-hidden='true'.** — Hidden or decorative elements with aria-hidden='true'.
- **Desktop-only administration tables with intentional horizontal table scrolling.** — Desktop-only administration tables with intentional horizontal table scrolling.
- **Ephemeral UI animations that do not shift layout or block the main thread.** — Ephemeral UI animations that do not shift layout or block the main thread.

## Scanners Executed by `cyberaudit-ui-ux-a11y` (10 modules)

- **`AccessibilityA11yScanner`** (*UI/UX Accessibility & WCAG Standards Scanner*): Audits markup and UI components for compliance with WCAG 2.1/2.2 accessibility, screen readers, and keyboard navigation.
- **`ResponsiveErgonomicsScanner`** (*UI/UX Responsive Layout & Touch Ergonomics Scanner*): Evaluates responsive viewport configurations, fluid reflow constraints, and touch target sizing.
- **`ContrastTypographyScanner`** (*UI/UX Color Contrast & Typography Usability Scanner*): Audits text-to-background contrast ratios, minimum font size thresholds, and anti-selection usability issues.
- **`UxAdvancedHeuristicsScanner`** (*Advanced UX Heuristics & Form Accessibility Scanner*): Audits focus visibility (killed outlines), duplicate DOM IDs, missing autocomplete semantics, and vestibular motion preferences.
- **`Wcag22ModernComplianceScanner`** (*WCAG 2.2 Modern Compliance & Assistive Tech Scanner*): Audits WCAG 2.2 criteria (paste prevention, focus obscuring), decorative SVG pollution, and placeholder label misuse.
- **`CognitiveErgonomicsScanner`** (*Cognitive Ergonomics & Usability Heuristics Scanner*): Audits Nielsen usability heuristics (unconfirmed destructive actions, error prevention), color-only status indicators, and dark mode contrast safety.
- **`AsyncUiStatesCompletenessScanner`** (*Async UI States Completeness Scanner (Loading/Error/Empty/Double-Submit)*): Audits frontend components for missing disabled/loading submit locks (double-submit bug), blocking browser alert() dialogs, and silent async catch blocks lacking UI error state.
- **`CoreWebVitalsAndFrontendPerfScanner`** (*Core Web Vitals (LCP, CLS, INP) & Frontend Performance Scanner*): Audits frontend templates and scripts for Cumulative Layout Shift (dimensionless <img>), non-passive scroll/touch listeners (INP jank), and render-blocking head scripts (LCP).
- **`DesignSystemTokenAndI18nScanner`** (*Design System Token Drift & i18n Ergonomics Scanner*): Detects magic z-index escalation (z-index >= 9999), inline hardcoded hex colors bypassing design tokens, and locale-naive currency formatting.
- **`ClientStorageAndHydrationSafetyScanner`** (*Client Storage Token Exposure & SSR Hydration Scanner*): Detects sensitive JWT/auth tokens or PII persisted in localStorage/sessionStorage and non-deterministic SSR hydration patterns.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-ui-ux-a11y . --threshold HIGH --json reports/cyberaudit-ui-ux-a11y-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-ui-ux-a11y --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-ui-ux-a11y:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
