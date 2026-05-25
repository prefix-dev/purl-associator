import type { OsvSeverity } from "./cves";

export type CvssMetricDisplayItem = {
  metric: string;
  value: string;
  metricCode: string;
  valueCode: string;
};

export type CvssBaseMetrics = {
  versionLabel: string;
  metricsUrl: string;
  items: CvssMetricDisplayItem[];
};

type MetricDefinition = {
  label: string;
  values: Record<string, string>;
};

type CvssDefinition = {
  versionLabel: string;
  metricsUrl: string;
  order: string[];
  metrics: Record<string, MetricDefinition>;
};

const CIA_VALUES = {
  H: "High",
  L: "Low",
  N: "None",
};

const CVSS_V2: CvssDefinition = {
  versionLabel: "CVSS v2",
  metricsUrl: "https://www.first.org/cvss/v2/guide#2-1-Base-Metrics",
  order: ["AV", "AC", "Au", "C", "I", "A"],
  metrics: {
    AV: {
      label: "Access vector",
      values: { L: "Local", A: "Adjacent network", N: "Network" },
    },
    AC: {
      label: "Access complexity",
      values: { H: "High", M: "Medium", L: "Low" },
    },
    Au: {
      label: "Authentication",
      values: { M: "Multiple", S: "Single", N: "None" },
    },
    C: {
      label: "Confidentiality impact",
      values: { N: "None", P: "Partial", C: "Complete" },
    },
    I: {
      label: "Integrity impact",
      values: { N: "None", P: "Partial", C: "Complete" },
    },
    A: {
      label: "Availability impact",
      values: { N: "None", P: "Partial", C: "Complete" },
    },
  },
};

const CVSS_V3: CvssDefinition = {
  versionLabel: "CVSS v3",
  metricsUrl: "https://www.first.org/cvss/v3-1/specification-document#Base-Metrics",
  order: ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
  metrics: {
    AV: {
      label: "Attack vector",
      values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    },
    AC: {
      label: "Attack complexity",
      values: { L: "Low", H: "High" },
    },
    PR: {
      label: "Privileges required",
      values: { N: "None", L: "Low", H: "High" },
    },
    UI: {
      label: "User interaction",
      values: { N: "None", R: "Required" },
    },
    S: {
      label: "Scope",
      values: { U: "Unchanged", C: "Changed" },
    },
    C: { label: "Confidentiality", values: CIA_VALUES },
    I: { label: "Integrity", values: CIA_VALUES },
    A: { label: "Availability", values: CIA_VALUES },
  },
};

const CVSS_V4: CvssDefinition = {
  versionLabel: "CVSS v4",
  metricsUrl: "https://www.first.org/cvss/v4-0/specification-document#Base-Metrics",
  order: ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"],
  metrics: {
    AV: {
      label: "Attack vector",
      values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    },
    AC: {
      label: "Attack complexity",
      values: { L: "Low", H: "High" },
    },
    AT: {
      label: "Attack requirements",
      values: { N: "None", P: "Present" },
    },
    PR: {
      label: "Privileges required",
      values: { N: "None", L: "Low", H: "High" },
    },
    UI: {
      label: "User interaction",
      values: { N: "None", P: "Passive", A: "Active" },
    },
    VC: { label: "Vulnerable system confidentiality", values: CIA_VALUES },
    VI: { label: "Vulnerable system integrity", values: CIA_VALUES },
    VA: { label: "Vulnerable system availability", values: CIA_VALUES },
    SC: { label: "Subsequent system confidentiality", values: CIA_VALUES },
    SI: {
      label: "Subsequent system integrity",
      values: { ...CIA_VALUES, S: "Safety" },
    },
    SA: {
      label: "Subsequent system availability",
      values: { ...CIA_VALUES, S: "Safety" },
    },
  },
};

function definitionFor(severity: OsvSeverity): CvssDefinition | undefined {
  if (severity.type === "CVSS_V2") return CVSS_V2;
  if (severity.type === "CVSS_V3") return CVSS_V3;
  if (severity.type === "CVSS_V4") return CVSS_V4;
  return undefined;
}

function parseVector(score: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of score.split("/")) {
    if (part.startsWith("CVSS:")) continue;
    const [key, value] = part.split(":", 2);
    if (key && value) out.set(key, value);
  }
  return out;
}

export function cvssBaseMetrics(
  severity: OsvSeverity | undefined,
): CvssBaseMetrics | undefined {
  if (!severity?.score) return undefined;
  const definition = definitionFor(severity);
  if (!definition) return undefined;

  const vector = parseVector(severity.score);
  const items: CvssMetricDisplayItem[] = [];
  for (const metricCode of definition.order) {
    const valueCode = vector.get(metricCode);
    const metric = definition.metrics[metricCode];
    if (!valueCode || !metric) continue;
    items.push({
      metric: metric.label,
      value: metric.values[valueCode] ?? valueCode,
      metricCode,
      valueCode,
    });
  }
  if (items.length === 0) return undefined;
  return {
    versionLabel: definition.versionLabel,
    metricsUrl: definition.metricsUrl,
    items,
  };
}

export function cvssBaseMetricDisplayItems(
  severity: OsvSeverity | undefined,
): CvssMetricDisplayItem[] {
  return cvssBaseMetrics(severity)?.items ?? [];
}
