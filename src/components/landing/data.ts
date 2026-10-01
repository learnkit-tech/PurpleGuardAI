import {
  Activity,
  Bot,
  BrainCircuit,
  Building2,
  Cloud,
  CloudCog,
  Code2,
  FileBarChart,
  FileCheck2,
  GitBranch,
  Globe,
  KeyRound,
  Landmark,
  LineChart,
  Network,
  Radar,
  Rocket,
  SearchCode,
  ServerCog,
  Shield,
  ShieldCheck,
  Sparkles,
  Stethoscope,
  Webhook,
  Wrench,
  type LucideIcon,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/* Navigation                                                          */
/* ------------------------------------------------------------------ */

export interface NavLink {
  label: string;
  href: string;
}

export const NAV_LINKS: NavLink[] = [
  { label: "Platform", href: "#platform" },
  { label: "ECC", href: "#ecc" },
  { label: "Solutions", href: "#solutions" },
  { label: "Technology", href: "#technology" },
  { label: "Pricing", href: "#pricing" },
  { label: "Docs", href: "#faq" },
  { label: "Blog", href: "#vision" },
  { label: "Contact", href: "#contact" },
];

/* ------------------------------------------------------------------ */
/* What is PurpleGuard AI                                              */
/* ------------------------------------------------------------------ */

export interface Capability {
  icon: LucideIcon;
  title: string;
  description: string;
}

export const CAPABILITIES: Capability[] = [
  {
    icon: SearchCode,
    title: "Static Code Analysis",
    description: "Every commit scanned across languages and frameworks at pull-request speed.",
  },
  {
    icon: BrainCircuit,
    title: "AI Vulnerability Detection",
    description: "LLM-driven detection that understands intent, not just patterns.",
  },
  {
    icon: KeyRound,
    title: "Secret Scanning",
    description: "Credentials, tokens, and keys caught before they ever reach production.",
  },
  {
    icon: Network,
    title: "Supply-Chain Security",
    description: "Dependencies, SBOMs, and provenance mapped end to end.",
  },
  {
    icon: CloudCog,
    title: "Cloud Security Analysis",
    description: "Misconfigurations across accounts, regions, and infrastructure as code.",
  },
  {
    icon: ServerCog,
    title: "Infrastructure Scanning",
    description: "Kubernetes, Terraform, and serverless workloads continuously audited.",
  },
  {
    icon: Wrench,
    title: "AI-Powered Remediation",
    description: "Secure, reviewed fixes generated for every finding — not just advice.",
  },
  {
    icon: FileCheck2,
    title: "Compliance Automation",
    description: "SOC 2, ISO 27001, and HIPAA evidence produced continuously.",
  },
  {
    icon: LineChart,
    title: "Predictive Risk Analysis",
    description: "Attack paths forecast before they are exploited.",
  },
];

/* ------------------------------------------------------------------ */
/* Features                                                            */
/* ------------------------------------------------------------------ */

export interface Feature {
  icon: LucideIcon;
  title: string;
  description: string;
}

export const FEATURES: Feature[] = [
  {
    icon: Radar,
    title: "AI Vulnerability Detection",
    description: "Semantic analysis across code, configs, and cloud state finds what signature scanners miss.",
  },
  {
    icon: BrainCircuit,
    title: "Security Reasoning Engine",
    description: "Every finding is reasoned through — root cause, exploitability, and blast radius.",
  },
  {
    icon: Wrench,
    title: "Autonomous Remediation",
    description: "Secure fixes generated, tested, and opened as verified pull requests.",
  },
  {
    icon: CloudCog,
    title: "Cloud Security",
    description: "Continuous posture management for AWS, GCP, Azure, and Kubernetes.",
  },
  {
    icon: Webhook,
    title: "API Security",
    description: "Authentication, authorization, and data-exposure risks in every endpoint.",
  },
  {
    icon: ServerCog,
    title: "Infrastructure Security",
    description: "Terraform, CloudFormation, and Helm scanned as code before deploy.",
  },
  {
    icon: Bot,
    title: "AI Agent Coordination",
    description: "ECC plans and delegates work across a fleet of specialized agents.",
  },
  {
    icon: FileBarChart,
    title: "Compliance Reports",
    description: "Audit-ready evidence mapped to SOC 2, ISO 27001, and HIPAA controls.",
  },
  {
    icon: Globe,
    title: "Threat Intelligence",
    description: "Real-time advisories, CVEs, and exploit activity fused into context.",
  },
  {
    icon: Sparkles,
    title: "Continuous Learning",
    description: "The engine improves its reasoning from every scan and incident.",
  },
  {
    icon: Activity,
    title: "Risk Prioritization",
    description: "Exploitable, business-critical risks surface first — noise is silenced.",
  },
  {
    icon: ShieldCheck,
    title: "Security Dashboard",
    description: "One glass pane for score, posture, agents, and autonomous actions.",
  },
];

/* ------------------------------------------------------------------ */
/* Why PurpleGuard — comparison                                         */
/* ------------------------------------------------------------------ */

export interface ComparisonRow {
  label: string;
  traditional: string;
  purpleguard: string;
}

export const COMPARISON_ROWS: ComparisonRow[] = [
  {
    label: "AI Reasoning",
    traditional: "Rule and signature matching",
    purpleguard: "LLM-native threat understanding",
  },
  {
    label: "Autonomous Agents",
    traditional: "Manual triage queues",
    purpleguard: "Self-coordinating security agents",
  },
  {
    label: "Automatic Fixes",
    traditional: "Advisory PDF reports",
    purpleguard: "Verified fixes, deployed safely",
  },
  {
    label: "Context Awareness",
    traditional: "Isolated alerts",
    purpleguard: "Full-stack knowledge graph",
  },
  {
    label: "Continuous Learning",
    traditional: "Quarterly rule updates",
    purpleguard: "Learns from every incident",
  },
  {
    label: "Cloud Security",
    traditional: "Optional bolt-on tooling",
    purpleguard: "Deep cloud-native scanning",
  },
  {
    label: "Supply Chain Security",
    traditional: "Dependency alerts only",
    purpleguard: "SBOMs and provenance, mapped",
  },
  {
    label: "Explainable AI",
    traditional: "Black-box results",
    purpleguard: "Reasoning shown for every finding",
  },
  {
    label: "Developer Guidance",
    traditional: "Ticket handoffs",
    purpleguard: "Inline fixes and pull requests",
  },
];

/* ------------------------------------------------------------------ */
/* Solutions                                                           */
/* ------------------------------------------------------------------ */

export interface Solution {
  icon: LucideIcon;
  title: string;
  description: string;
}

export const SOLUTIONS: Solution[] = [
  {
    icon: Code2,
    title: "Developers",
    description: "Findings and fixes live inside your pull request — no context switching.",
  },
  {
    icon: GitBranch,
    title: "DevSecOps",
    description: "Security gates that keep pipelines fast while blocking real risk.",
  },
  {
    icon: Rocket,
    title: "Startups",
    description: "Enterprise-grade posture from day one, without a security team.",
  },
  {
    icon: Building2,
    title: "Enterprise",
    description: "Scale across thousands of repos, services, and cloud accounts.",
  },
  {
    icon: Landmark,
    title: "Banks",
    description: "Regulatory-grade evidence and continuous control monitoring.",
  },
  {
    icon: Stethoscope,
    title: "Healthcare",
    description: "HIPAA-aligned scanning and audit trails for protected systems.",
  },
  {
    icon: Shield,
    title: "Government",
    description: "Compliance frameworks, air-gapped deploys, and zero-trust defaults.",
  },
  {
    icon: Bot,
    title: "AI Companies",
    description: "Prompt injection, model theft, and data-exposure defense for AI stacks.",
  },
  {
    icon: Cloud,
    title: "Cloud Providers",
    description: "Tenant-aware scanning across massive multi-account estates.",
  },
];

/* ------------------------------------------------------------------ */
/* Roadmap                                                             */
/* ------------------------------------------------------------------ */

export interface RoadmapItem {
  year: string;
  title: string;
  description: string;
}

export const ROADMAP: RoadmapItem[] = [
  {
    year: "2026",
    title: "AI Code Scanner",
    description: "The first PurpleGuard scanner ships — semantic detection across every major language.",
  },
  {
    year: "2027",
    title: "ECC Multi-Agent Reasoning",
    description: "Enterprise Cyber Command learns to plan investigations and coordinate specialist agents.",
  },
  {
    year: "2028",
    title: "Autonomous Security Operations",
    description: "ECC plans, validates, fixes, and verifies — with human oversight by default.",
  },
  {
    year: "2029",
    title: "Enterprise Security Cloud",
    description: "A unified cloud where code, infrastructure, and compliance posture converge.",
  },
  {
    year: "2030",
    title: "Global AI Cyber Defense Network",
    description: "An interconnected defense grid where learning compounds across every member.",
  },
];

/* ------------------------------------------------------------------ */
/* FAQ                                                                 */
/* ------------------------------------------------------------------ */

export interface Faq {
  question: string;
  answer: string;
}

export const FAQS: Faq[] = [
  {
    question: "How is PurpleGuard AI different from traditional scanners?",
    answer:
      "Traditional tools match known patterns. PurpleGuard AI reasons about what the code and cloud actually do — combining static analysis, a knowledge graph of your entire stack, and LLM-based reasoning to detect issues that never appear in a signature database.",
  },
  {
    question: "What exactly does ECC do?",
    answer:
      "ECC — Enterprise Cyber Command — is the intelligence layer. It plans investigations, coordinates specialized AI agents, validates their findings, generates secure fixes, verifies remediation, and feeds every outcome back into its reasoning so it gets smarter over time.",
  },
  {
    question: "Do autonomous agents fix things without my permission?",
    answer:
      "Never by default. Autonomous fixes are generated as verified pull requests with full reasoning attached, so your team reviews and merges. Fully automated remediation is available as an opt-in policy for low-risk classes of findings.",
  },
  {
    question: "How is my source code handled?",
    answer:
      "Your code is encrypted in transit and at rest, isolated per tenant, and never used to train shared models. You choose the region, and enterprise plans support private networking and on-premise deployment for the entire engine.",
  },
  {
    question: "Which languages, clouds, and frameworks are supported?",
    answer:
      "Scanners cover the major languages including JavaScript, TypeScript, Python, Go, Java, Rust, and C#, plus Terraform, CloudFormation, Helm, Docker, and Kubernetes for infrastructure. AWS, GCP, and Azure are supported natively.",
  },
  {
    question: "How does PurpleGuard AI integrate with my workflow?",
    answer:
      "Native GitHub, GitLab, and Bitbucket integrations, a REST API, webhooks, and CI/CD gates. Findings appear as inline pull-request comments with suggested fixes, so security follows your existing process.",
  },
  {
    question: "Can it help with compliance reporting?",
    answer:
      "Yes. ECC continuously maps evidence to controls for SOC 2, ISO 27001, HIPAA, and PCI DSS, producing audit-ready reports without the end-of-quarter scramble.",
  },
  {
    question: "How does pricing work?",
    answer:
      "Pricing scales with repositories and cloud assets, not per-seat agents. Start free for small teams and grow to enterprise plans with dedicated infrastructure, SSO, and support SLAs.",
  },
];

/* ------------------------------------------------------------------ */
/* Footer                                                              */
/* ------------------------------------------------------------------ */

export interface FooterColumn {
  heading: string;
  links: { label: string; href: string }[];
}

export const FOOTER_COLUMNS: FooterColumn[] = [
  {
    heading: "Platform",
    links: [
      { label: "Platform", href: "#platform" },
      { label: "ECC", href: "#ecc" },
      { label: "Solutions", href: "#solutions" },
      { label: "Technology", href: "#technology" },
      { label: "Pricing", href: "#pricing" },
    ],
  },
  {
    heading: "Resources",
    links: [
      { label: "Docs", href: "#faq" },
      { label: "API", href: "#faq" },
      { label: "GitHub", href: "#contact" },
      { label: "Blog", href: "#vision" },
    ],
  },
  {
    heading: "Company",
    links: [
      { label: "Privacy", href: "#contact" },
      { label: "Terms", href: "#contact" },
      { label: "Contact", href: "#contact" },
      { label: "LinkedIn", href: "#contact" },
      { label: "X", href: "#contact" },
    ],
  },
];

/* ------------------------------------------------------------------ */
/* Console mock data                                                   */
/* ------------------------------------------------------------------ */

export interface Activity {
  id: string;
  tone: "violet" | "emerald" | "amber" | "cyan" | "rose";
  text: string;
}

export const HERO_ACTIVITY: Activity[] = [
  { id: "scan-1", tone: "violet", text: "scan: api-gateway — 214 files analyzed" },
  { id: "cloud-1", tone: "cyan", text: "cloud: us-east-1 — 12 assets monitored" },
  { id: "alert-1", tone: "amber", text: "alert: exposed secret in auth-service/.env" },
  { id: "agent-1", tone: "emerald", text: "agent: supply-chain dispatched to investigate" },
  { id: "fix-1", tone: "violet", text: "fix: patched axios 1.6.0 → 1.7.9 (CVE-2024-…)" },
  { id: "verify-1", tone: "emerald", text: "verify: remediation confirmed in staging" },
  { id: "reason-1", tone: "cyan", text: "reason: ECC planning investigation #4821" },
  { id: "alert-2", tone: "rose", text: "alert: misconfigured IAM role — prod-read" },
  { id: "deploy-1", tone: "emerald", text: "deploy: verified fix merged to main" },
  { id: "scan-2", tone: "violet", text: "scan: payments-core — 87 files analyzed" },
];

export const AGENT_ACTIVITY: { agent: string; role: string; status: string; tone: "emerald" | "violet" | "amber" | "cyan" }[] = [
  { agent: "sentinel-01", role: "repo scanning", status: "analyzing 214 files", tone: "violet" },
  { agent: "sentinel-02", role: "cloud posture", status: "checking 12 accounts", tone: "cyan" },
  { agent: "sentinel-03", role: "secret hunt", status: "reviewing 1,480 commits", tone: "amber" },
  { agent: "sentinel-04", role: "supply chain", status: "mapping SBOM · 3,412 deps", tone: "emerald" },
  { agent: "sentinel-05", role: "remediation", status: "building fix for CVE-2024-1234", tone: "violet" },
  { agent: "sentinel-06", role: "compliance", status: "updating SOC 2 evidence", tone: "cyan" },
];

export const RECENT_SCANS: {
  repo: string;
  status: string;
  statusTone: "emerald" | "amber" | "violet" | "cyan";
  findings: number;
  duration: string;
}[] = [
  { repo: "payments-core", status: "verified", statusTone: "emerald", findings: 3, duration: "0:42" },
  { repo: "auth-service", status: "fixing", statusTone: "amber", findings: 7, duration: "1:08" },
  { repo: "api-gateway", status: "clean", statusTone: "emerald", findings: 0, duration: "0:31" },
  { repo: "mobile-client", status: "reviewing", statusTone: "violet", findings: 4, duration: "1:22" },
  { repo: "data-lake-etl", status: "clean", statusTone: "emerald", findings: 0, duration: "0:57" },
  { repo: "terraform-prod", status: "fixing", statusTone: "cyan", findings: 2, duration: "0:36" },
];

export const AI_RECOMMENDATIONS: string[] = [
  "Rotate the leaked AWS key in auth-service within 24h — exposed in 3 repos.",
  "Apply least-privilege to the payments IAM role; 14 unused permissions found.",
  "Upgrade lodash in 11 packages — 2 reachable paths from public endpoints.",
  "Enable mandatory MFA on the admin console before the next penetration test.",
];

export const HEATMAP_CELLS = 8 * 12;

export function heatmapIntensity(index: number): number {
  // Deterministic pseudo-random intensity (0–3) for a stable, credible heatmap.
  const seed = (index * 2654435761) % 9973;
  const noise = ((seed * seed * seed) % 9973) / 9973;
  return noise < 0.42 ? 0 : noise < 0.7 ? 1 : noise < 0.9 ? 2 : 3;
}

/* ------------------------------------------------------------------ */
/* Pricing                                                             */
/* ------------------------------------------------------------------ */

export interface PricingPlan {
  name: string;
  tagline: string;
  price: string;
  cadence: string;
  featured?: boolean;
  cta: string;
  features: string[];
}

export const PRICING_PLANS: PricingPlan[] = [
  {
    name: "Starter",
    tagline: "For individuals and side projects.",
    price: "$0",
    cadence: "free forever",
    cta: "Start scanning",
    features: [
      "Up to 3 repositories",
      "Static + secret scanning",
      "Weekly AI risk digest",
      "Community support",
    ],
  },
  {
    name: "Pro",
    tagline: "For teams shipping in production.",
    price: "$99",
    cadence: "per month",
    featured: true,
    cta: "Start 14-day trial",
    features: [
      "25 repositories",
      "ECC multi-agent reasoning",
      "Autonomous fixes as pull requests",
      "Cloud + infrastructure scanning",
      "Compliance evidence (SOC 2)",
      "Priority support",
    ],
  },
  {
    name: "Scale",
    tagline: "For growing security estates.",
    price: "$499",
    cadence: "per month",
    cta: "Talk to sales",
    features: [
      "Unlimited repositories",
      "Multi-region cloud posture",
      "Advanced agent coordination",
      "Custom policy engine",
      "SSO / SAML",
    ],
  },
];

/* ------------------------------------------------------------------ */
/* Findings (dashboard)                                                */
/* ------------------------------------------------------------------ */

export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "verified" | "fixing" | "open";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  repo: string;
  status: FindingStatus;
  agent: string;
}

export const FINDINGS: Finding[] = [
  {
    id: "F-2841",
    title: "Exposed AWS secret in auth-service/.env",
    severity: "critical",
    repo: "auth-service",
    status: "fixing",
    agent: "sentinel-03",
  },
  {
    id: "F-2839",
    title: "SQL injection in /api/v2/orders search",
    severity: "high",
    repo: "payments-core",
    status: "verified",
    agent: "sentinel-01",
  },
  {
    id: "F-2835",
    title: "IAM role over-permissioned — 14 unused actions",
    severity: "high",
    repo: "terraform-prod",
    status: "open",
    agent: "sentinel-02",
  },
  {
    id: "F-2832",
    title: "CVE-2024-1234 in lodash — reachable in 11 packages",
    severity: "medium",
    repo: "api-gateway",
    status: "verified",
    agent: "sentinel-04",
  },
  {
    id: "F-2829",
    title: "SSRF risk in image proxy allowlist",
    severity: "medium",
    repo: "mobile-client",
    status: "open",
    agent: "sentinel-01",
  },
  {
    id: "F-2824",
    title: "Hardcoded JWT signing key in config",
    severity: "critical",
    repo: "data-lake-etl",
    status: "verified",
    agent: "sentinel-03",
  },
  {
    id: "F-2821",
    title: "Missing MFA enforcement on admin console",
    severity: "high",
    repo: "admin-console",
    status: "fixing",
    agent: "sentinel-06",
  },
  {
    id: "F-2818",
    title: "Deprecated TLS 1.0 allowed on load balancer",
    severity: "low",
    repo: "terraform-prod",
    status: "verified",
    agent: "sentinel-02",
  },
];
