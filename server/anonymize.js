"use strict";

/**
 * Anonymized sample export.
 *
 * The user configures one or more JSON Pointer patterns (RFC 6901 escaping,
 * plus a single-segment "*" wildcard matching any object key or array index).
 * Every pattern is matched recursively against each sample:
 *
 *   - illegal pointer               -> the export is refused (422)
 *   - match lands on object / array  -> refused (only scalars are anonymized)
 *   - two patterns hit the same path -> refused (ambiguous ownership)
 *
 * Matched scalar values are replaced with deterministic tokens that are
 * stable across samples within one rule: the same original value always maps
 * to the same replacement, different originals never merge, and the JSON type
 * is preserved — strings stay strings, integers stay integers (never become
 * decimals), non-integer numbers stay non-integer, booleans and null pass
 * through unchanged (their type leaves no room for distinct tokens).
 *
 * Refusals still carry the per-rule match statistics (hits, missed samples)
 * plus the concrete offending positions, so the UI can show what happened.
 * A single export is capped at MAX_SAMPLES samples and MAX_RULES rules.
 */

const crypto = require("node:crypto");
const { escapePointer } = require("./infer");

const MAX_SAMPLES = 200;
const MAX_RULES = 50;
// Error detail lists are capped so pathological rule sets cannot produce
// unbounded responses; the totals always reflect the real counts.
const MAX_DETAIL_ENTRIES = 50;

const WILDCARD = Symbol("wildcard");

const POINTER_HINT =
  'JSON Pointer 须以 "/" 开头，"~" 仅允许写作 ~0（表示 ~）或 ~1（表示 /），单段 * 为通配符';

// RFC 6901 array index: "0" or digits without a leading zero.
const ARRAY_INDEX = /^(0|[1-9]\d*)$/;

/**
 * Parse a pattern into segments; a segment that is exactly "*" becomes the
 * WILDCARD marker (a literal key named "*" therefore cannot be addressed).
 * Returns null when the pointer is malformed: not starting with "/" or
 * carrying an illegal "~" escape (RFC 6901 defines only ~0 and ~1).
 */
function parsePattern(pattern) {
  if (typeof pattern !== "string") return null;
  if (pattern === "") return [];
  if (!pattern.startsWith("/")) return null;
  const segments = [];
  for (const raw of pattern.slice(1).split("/")) {
    let segment = "";
    for (let i = 0; i < raw.length; i += 1) {
      const ch = raw[i];
      if (ch !== "~") {
        segment += ch;
        continue;
      }
      const next = raw[i + 1];
      if (next === "0") segment += "~";
      else if (next === "1") segment += "/";
      else return null;
      i += 1;
    }
    segments.push(segment === "*" ? WILDCARD : segment);
  }
  return segments;
}

/** Format a matched path (unescaped segment array) for display. */
function formatPath(segments) {
  if (segments.length === 0) return "(root)";
  return `/${segments.map(escapePointer).join("/")}`;
}

/**
 * Recursively collect every position the pattern segments match, descending
 * into all object keys / array elements at "*" segments. Literal segments
 * address object keys and — per RFC 6901 — numeric array indices.
 */
function collectMatches(value, segments, path, out) {
  if (segments.length === 0) {
    out.push({ path, value });
    return;
  }
  const [head, ...rest] = segments;
  if (head === WILDCARD) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        collectMatches(item, rest, [...path, String(index)], out);
      });
    } else if (value !== null && typeof value === "object") {
      for (const key of Object.keys(value)) {
        collectMatches(value[key], rest, [...path, key], out);
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    if (ARRAY_INDEX.test(head)) {
      const index = Number(head);
      if (index < value.length) {
        collectMatches(value[index], rest, [...path, String(index)], out);
      }
    }
    return;
  }
  if (
    value !== null &&
    typeof value === "object" &&
    Object.prototype.hasOwnProperty.call(value, head)
  ) {
    collectMatches(value[head], rest, [...path, head], out);
  }
}

function scalarKind(value) {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return "string";
    case "boolean":
      return "boolean";
    default:
      return Number.isInteger(value) ? "integer" : "number";
  }
}

/**
 * Deterministic per-rule value mapper. Replacements derive from a salted
 * SHA-256 of the original value, so the mapping is stable across samples and
 * across runs; a "taken" registry guarantees distinct originals never merge
 * into the same replacement (hash collisions are resolved by probing).
 */
function createReplacer(salt) {
  const seen = new Map(); // canonical original -> replacement
  const taken = new Set(); // serialized replacements already handed out

  function replace(value) {
    const kind = scalarKind(value);
    const key = `${kind}:${JSON.stringify(value)}`;
    if (seen.has(key)) return seen.get(key);
    const hex = crypto
      .createHash("sha256")
      .update(`jcs-anonymize:v1:${salt}:${key}`)
      .digest("hex");
    let replacement;
    if (kind === "string") {
      let candidate = `anon_${hex.slice(0, 12)}`;
      for (let n = 2; taken.has(`string:${candidate}`); n += 1) {
        candidate = `anon_${hex.slice(0, 12)}_${n}`;
      }
      replacement = candidate;
    } else if (kind === "integer") {
      // 13 hex digits < 2^52: always an exact safe integer.
      let candidate = parseInt(hex.slice(0, 13), 16);
      while (taken.has(`integer:${candidate}`)) candidate += 1;
      replacement = candidate;
    } else if (kind === "number") {
      // x.5 fractions can never collapse into an integer.
      let candidate = parseInt(hex.slice(0, 12), 16) + 0.5;
      while (taken.has(`number:${candidate}`)) candidate += 1;
      replacement = candidate;
    } else {
      // boolean / null: the type leaves no room for distinct tokens.
      replacement = value;
    }
    seen.set(key, replacement);
    taken.add(`${kind}:${JSON.stringify(replacement)}`);
    return replacement;
  }

  return { replace, distinctCount: () => seen.size };
}

/** Assign `replacement` at `path` inside the cloned sample list. */
function setAtPath(clones, sampleIndex, path, replacement) {
  if (path.length === 0) {
    clones[sampleIndex] = replacement;
    return;
  }
  let node = clones[sampleIndex];
  for (let i = 0; i < path.length - 1; i += 1) {
    node = node[path[i]];
  }
  node[path[path.length - 1]] = replacement;
}

/**
 * Match every rule against every sample and anonymize the matched scalars.
 *
 * @returns {{ totalSamples: number, replacedCount: number,
 *            rules: Array<{ index: number, pattern: string, hits: number,
 *                            distinctValues: number, missedSamples: number[] }>,
 *            samples: any[] }}
 */
function anonymizeSamples({ samples, rules }) {
  if (!Array.isArray(samples) || samples.length === 0) {
    throw Object.assign(new Error("Request body must contain a non-empty 'samples' array."), {
      status: 400,
    });
  }
  if (samples.length > MAX_SAMPLES) {
    throw Object.assign(
      new Error(
        `Too many samples: got ${samples.length}, at most ${MAX_SAMPLES} allowed per export.`
      ),
      { status: 400 }
    );
  }
  if (!Array.isArray(rules) || rules.length === 0) {
    throw Object.assign(
      new Error("Request body must contain a non-empty 'rules' array of JSON Pointer patterns."),
      { status: 400 }
    );
  }
  if (rules.length > MAX_RULES) {
    throw Object.assign(
      new Error(`Too many rules: got ${rules.length}, at most ${MAX_RULES} allowed per export.`),
      { status: 400 }
    );
  }
  for (const rule of rules) {
    if (typeof rule !== "string") {
      throw Object.assign(new Error("Every rule must be a JSON Pointer string."), { status: 400 });
    }
  }

  // Phase 1: parse patterns and collect matches for every rule/sample pair.
  const ruleStats = [];
  const parsedRules = [];
  const nonScalarHits = [];
  const claims = new Map(); // sampleIndex -> Map(pointer -> Set of rule indexes)

  rules.forEach((pattern, index) => {
    const segments = parsePattern(pattern);
    if (segments === null) {
      ruleStats.push({ index, pattern, error: `JSON Pointer 非法。${POINTER_HINT}。` });
      parsedRules.push(null);
      return;
    }
    const matches = [];
    samples.forEach((sample, sampleIndex) => {
      const found = [];
      collectMatches(sample, segments, [], found);
      for (const match of found) {
        const pointer = formatPath(match.path);
        if (match.value !== null && typeof match.value === "object") {
          nonScalarHits.push({
            rule: index,
            pattern,
            sample: sampleIndex,
            path: pointer,
            type: Array.isArray(match.value) ? "array" : "object",
          });
        }
        let byPath = claims.get(sampleIndex);
        if (!byPath) {
          byPath = new Map();
          claims.set(sampleIndex, byPath);
        }
        let owners = byPath.get(pointer);
        if (!owners) {
          owners = new Set();
          byPath.set(pointer, owners);
        }
        owners.add(index);
        matches.push({ sampleIndex, path: match.path, value: match.value });
      }
    });
    const hitSamples = new Set(matches.map((m) => m.sampleIndex));
    ruleStats.push({
      index,
      pattern,
      hits: matches.length,
      missedSamples: samples.map((_, i) => i).filter((i) => !hitSamples.has(i)),
    });
    parsedRules.push({ matches });
  });

  // Phase 2: a path claimed by more than one rule is ambiguous — refuse.
  const conflicts = [];
  for (const [sampleIndex, byPath] of claims) {
    for (const [pointer, owners] of byPath) {
      if (owners.size > 1) {
        conflicts.push({ sample: sampleIndex, path: pointer, rules: [...owners].sort((a, b) => a - b) });
      }
    }
  }
  conflicts.sort((a, b) => a.sample - b.sample || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const ruleErrorCount = ruleStats.filter((r) => r.error).length;
  if (ruleErrorCount > 0 || nonScalarHits.length > 0 || conflicts.length > 0) {
    const problems = [];
    if (ruleErrorCount > 0) problems.push(`${ruleErrorCount} 条规则的 Pointer 非法`);
    if (nonScalarHits.length > 0) {
      problems.push(`${nonScalarHits.length} 处命中了对象或数组（仅支持匿名化标量值）`);
    }
    if (conflicts.length > 0) problems.push(`${conflicts.length} 处路径被多条规则同时命中`);
    throw Object.assign(new Error(`已拒绝生成匿名化样本：${problems.join("；")}。`), {
      status: 422,
      details: {
        rules: ruleStats,
        nonScalarHits: {
          total: nonScalarHits.length,
          entries: nonScalarHits.slice(0, MAX_DETAIL_ENTRIES),
        },
        conflicts: {
          total: conflicts.length,
          entries: conflicts.slice(0, MAX_DETAIL_ENTRIES),
        },
      },
    });
  }

  // Phase 3: replace. The per-rule replacer keeps the mapping stable across
  // samples; the originals are never mutated.
  const anonymized = samples.map((sample) => structuredClone(sample));
  let replacedCount = 0;
  parsedRules.forEach((parsed, index) => {
    const replacer = createReplacer(rules[index]);
    for (const match of parsed.matches) {
      setAtPath(anonymized, match.sampleIndex, match.path, replacer.replace(match.value));
      replacedCount += 1;
    }
    ruleStats[index].distinctValues = replacer.distinctCount();
  });

  return {
    totalSamples: samples.length,
    replacedCount,
    rules: ruleStats,
    samples: anonymized,
  };
}

module.exports = { anonymizeSamples, parsePattern, MAX_SAMPLES, MAX_RULES, POINTER_HINT };
