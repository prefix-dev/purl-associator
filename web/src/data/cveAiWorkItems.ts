import type {
  AiDraft,
  AiDraftsPayload,
  AiQueuePayload,
  CveAdvisoryIndex,
  CvePackageIndex,
  ReviewEdit,
} from "./cves";

export type CveAiWorkMode = "queue" | "drafts";

export type CveAiWorkRow = {
  pkg: CvePackageIndex;
  adv: CveAdvisoryIndex;
  score: number;
  reviewed: boolean;
  queued: boolean;
  drafted: boolean;
  draft?: AiDraft;
  locallyQueued: boolean;
  packageQueueCount: number;
};

export function reviewStatusIsResolved(status: string | undefined): boolean {
  return !!status && status !== "under_investigation";
}

export function cveReviewKey(pkg: string, advisoryId: string): string {
  return `${pkg}::${advisoryId}`;
}

export function packageDraft(
  aiDrafts: AiDraftsPayload | null,
  packages: string[],
  advisoryId: string,
): AiDraft | undefined {
  for (const pkg of packages) {
    const draft = aiDrafts?.drafts[pkg]?.[advisoryId];
    if (draft) return draft;
  }
  return undefined;
}

export function packageQueued(
  aiQueue: AiQueuePayload | null,
  packages: string[],
  advisoryId: string,
): boolean {
  return packages.some((pkg) => Boolean(aiQueue?.queue[pkg]?.[advisoryId]));
}

export function locallyQueued(
  enqueued: Set<string>,
  packages: string[],
  advisoryId: string,
): boolean {
  return packages.some((pkg) => enqueued.has(cveReviewKey(pkg, advisoryId)));
}

export function aiStatusChangeLabel(adv: CveAdvisoryIndex, draft: AiDraft): string {
  const current = adv.vex_status ?? "unreviewed";
  return current === draft.openvex_status
    ? `keeps ${draft.openvex_status}`
    : `${current} → ${draft.openvex_status}`;
}

export function draftNeedsCloserRead(draft: AiDraft): boolean {
  return (
    !draft.affected_versions.agrees_with_match ||
    draft.runtime_applicability.applies === "unknown" ||
    draft.runtime_applicability.applies === "partial" ||
    draft.severity_in_conda_context.assessment === "unknown"
  );
}

export function buildCveAiWorkRows({
  mode,
  packages,
  membersByRep,
  edits,
  aiDrafts,
  aiQueue,
  enqueuedAdvisories,
  includeCurrentKey,
}: {
  mode: CveAiWorkMode;
  packages: CvePackageIndex[];
  membersByRep: Map<string, string[]>;
  edits: Record<string, ReviewEdit>;
  aiDrafts: AiDraftsPayload | null;
  aiQueue: AiQueuePayload | null;
  enqueuedAdvisories: Set<string>;
  /** Used by Apply & next: keep the just-applied row while choosing the next one. */
  includeCurrentKey?: string;
}): CveAiWorkRow[] {
  const out: CveAiWorkRow[] = [];
  for (const pkg of packages) {
    const lookupPackages = membersByRep.get(pkg.package) ?? [pkg.package];
    for (const adv of pkg.advisories) {
      const key = cveReviewKey(pkg.package, adv.id);
      const draft = packageDraft(aiDrafts, lookupPackages, adv.id);
      const drafted = Boolean(draft);
      const queued = packageQueued(aiQueue, lookupPackages, adv.id);
      const locallyQueued_ = locallyQueued(enqueuedAdvisories, lookupPackages, adv.id);
      const reviewed = reviewStatusIsResolved(edits[key]?.status ?? adv.vex_status);
      if (mode === "drafts") {
        if (!drafted || (reviewed && key !== includeCurrentKey)) continue;
      } else {
        if (!queued || drafted || reviewed) continue;
      }
      out.push({
        pkg,
        adv,
        score: adv.severity?.score_num ?? 0,
        reviewed,
        queued,
        drafted,
        draft,
        locallyQueued: locallyQueued_,
        packageQueueCount: 0,
      });
    }
  }
  const counts = new Map<string, number>();
  for (const row of out) counts.set(row.pkg.package, (counts.get(row.pkg.package) ?? 0) + 1);
  for (const row of out) row.packageQueueCount = counts.get(row.pkg.package) ?? 1;
  out.sort((a, b) => {
    if (a.score !== b.score) return b.score - a.score;
    return a.adv.primary_id.localeCompare(b.adv.primary_id) || a.pkg.package.localeCompare(b.pkg.package);
  });
  return out;
}
