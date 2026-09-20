import { useState } from "react";
import { anonymizeSamples } from "../api.js";

// Keep in sync with MAX_SAMPLES / MAX_RULES in server/anonymize.js.
const MAX_SAMPLES = 200;
const MAX_RULES = 50;

/**
 * Anonymized export, shown inside the sample input panel. The user configures
 * JSON Pointer rules (RFC 6901 escaping, plus a single-segment "*" wildcard
 * for object keys / array indices); the backend matches them recursively
 * across the samples and replaces the matched scalars with cross-sample
 * stable, type-preserving tokens.
 *
 * The outcome is stored together with a signature of its inputs (rule texts +
 * sample texts): editing either invalidates the displayed preview, the same
 * convention as the contribution analysis and the variant contract. Refusals
 * (HTTP 422) still carry the per-rule hit statistics plus the concrete
 * illegal pointers, object/array hits and rule conflicts, which are rendered
 * so the user can fix the rules.
 */
export default function AnonymizePanel({ samples, allValid, signature }) {
  const [rules, setRules] = useState([""]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null); // client-side pre-check failure
  const [outcome, setOutcome] = useState(null); // { signature, ok, data, message? }
  const [copied, setCopied] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  // Empty rows are ignored; the remaining trimmed rules are what gets sent.
  const trimmedRules = rules.map((r) => r.trim()).filter((r) => r !== "");
  const runSignature = JSON.stringify([trimmedRules, signature]);
  const current = outcome && outcome.signature === runSignature ? outcome : null;
  const invalidated = outcome !== null && outcome.signature !== runSignature;

  const data = current && current.ok ? current.data : null;
  const failure = current && !current.ok ? current : null;
  // A 422 body keeps the match analysis: surface it next to the refusal.
  const failureDetails = failure && failure.data && typeof failure.data === "object"
    ? failure.data
    : null;
  const ruleResults = data ? data.rules : failureDetails?.rules ?? null;
  const nonScalarHits = !data && failureDetails ? failureDetails.nonScalarHits : null;
  const conflicts = !data && failureDetails ? failureDetails.conflicts : null;

  function updateRule(index, text) {
    setRules((prev) => prev.map((r, i) => (i === index ? text : r)));
  }

  function addRule() {
    setRules((prev) => [...prev, ""]);
  }

  function removeRule(index) {
    setRules((prev) => prev.filter((_, i) => i !== index));
  }

  async function run() {
    setError(null);
    if (samples.length > MAX_SAMPLES) {
      setOutcome(null);
      setError(
        `单次最多匿名化 ${MAX_SAMPLES} 条样本，当前输入共 ${samples.length} 条，请删减后再生成。`
      );
      return;
    }
    if (trimmedRules.length > MAX_RULES) {
      setOutcome(null);
      setError(`单次最多 ${MAX_RULES} 条规则，当前共 ${trimmedRules.length} 条，请删减后再生成。`);
      return;
    }
    setBusy(true);
    try {
      const result = await anonymizeSamples(samples, trimmedRules);
      setOutcome({ signature: runSignature, ok: true, data: result });
      setCopied(false);
      setShowPreview(false);
    } catch (e) {
      setOutcome({ signature: runSignature, ok: false, message: e.message, data: e.data });
      setCopied(false);
      setShowPreview(false);
    } finally {
      setBusy(false);
    }
  }

  async function copySamples() {
    if (!data) return;
    const text = JSON.stringify(data.samples, null, 2);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="anonymize">
      <div className="scan-head">
        <span className="panel-label">匿名化导出</span>
        <span className="panel__meta">
          按 JSON Pointer 规则递归匹配标量值并替换为跨样本稳定的匿名值（类型保持不变，单段 *
          可通配对象键或数组下标，单次最多 {MAX_SAMPLES} 条样本 / {MAX_RULES} 条规则）
        </span>
      </div>

      <div className="anonymize-rules">
        {rules.map((rule, i) => (
          <div className="anonymize-rule" key={i}>
            <span className="anonymize-rule__label">规则 {i + 1}</span>
            <input
              className="anonymize-rule__input"
              value={rule}
              onChange={(e) => updateRule(i, e.target.value)}
              placeholder="例如 /email 或 /users/*/phone（~ 写作 ~0，/ 写作 ~1）"
              spellCheck={false}
            />
            {rules.length > 1 && (
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                onClick={() => removeRule(i)}
              >
                删除
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="actions">
        <button
          type="button"
          className="btn btn--sm"
          onClick={addRule}
          disabled={rules.length >= MAX_RULES}
        >
          + 添加规则
        </button>
        <button
          type="button"
          className="btn btn--primary"
          onClick={run}
          disabled={busy || !allValid || samples.length === 0 || trimmedRules.length === 0}
          title={
            !allValid
              ? "请先修正无效的 JSON 样本"
              : trimmedRules.length === 0
                ? "请至少填写一条 JSON Pointer 规则"
                : ""
          }
        >
          {busy ? "生成中…" : "生成匿名化预览"}
        </button>
      </div>

      {error && <div className="alert alert--err">{error}</div>}
      {invalidated && (
        <div className="alert alert--info">规则或样本内容已变化，上次预览已失效，请重新生成。</div>
      )}
      {failure && <div className="alert alert--err">{failure.message}</div>}

      {ruleResults && ruleResults.length > 0 && (
        <ul className="anonymize-rule-results">
          {ruleResults.map((r) => (
            <li
              key={r.index}
              className={`anonymize-rule-result ${r.error ? "anonymize-rule-result--err" : ""}`}
            >
              <div className="anonymize-rule-result__head">
                <span className="anonymize-rule-result__label">规则 {r.index + 1}</span>
                <code className="anonymize-rule-result__pattern">{r.pattern}</code>
                {r.error ? (
                  <span className="variant-chip variant-chip--skip">Pointer 非法</span>
                ) : (
                  <>
                    <span className="variant-chip variant-chip--ok">命中 {r.hits} 处</span>
                    {typeof r.distinctValues === "number" && (
                      <span className="variant-chip">替换 {r.distinctValues} 个不同取值</span>
                    )}
                  </>
                )}
              </div>
              <div className="anonymize-rule-result__meta">
                {r.error
                  ? r.error
                  : r.missedSamples.length === 0
                    ? "全部样本均命中"
                    : `未命中：${r.missedSamples.map((i) => `样本 ${i + 1}`).join("、")}`}
              </div>
            </li>
          ))}
        </ul>
      )}

      {nonScalarHits && nonScalarHits.entries.length > 0 && (
        <div className="anonymize-detail-block">
          <div className="panel__meta">
            命中对象或数组（共 {nonScalarHits.total} 处，仅支持匿名化标量值）：
          </div>
          <ul className="variant-skipped">
            {nonScalarHits.entries.map((h, i) => (
              <li key={i}>
                <code>
                  样本 {h.sample + 1} {h.path}
                </code>
                规则 {h.rule + 1} 命中{h.type === "array" ? "数组" : "对象"}
              </li>
            ))}
          </ul>
          {nonScalarHits.total > nonScalarHits.entries.length && (
            <div className="panel__meta">
              …其余 {nonScalarHits.total - nonScalarHits.entries.length} 处从略
            </div>
          )}
        </div>
      )}

      {conflicts && conflicts.entries.length > 0 && (
        <div className="anonymize-detail-block">
          <div className="panel__meta">
            不同规则命中了同一路径（共 {conflicts.total} 处）：
          </div>
          <ul className="variant-skipped">
            {conflicts.entries.map((c, i) => (
              <li key={i}>
                <code>
                  样本 {c.sample + 1} {c.path}
                </code>
                被规则 {c.rules.map((r) => r + 1).join("、")} 同时命中
              </li>
            ))}
          </ul>
          {conflicts.total > conflicts.entries.length && (
            <div className="panel__meta">…其余 {conflicts.total - conflicts.entries.length} 处从略</div>
          )}
        </div>
      )}

      {data && (
        <>
          <div className="anonymize-summary">
            <span className="variant-chip variant-chip--ok">已替换 {data.replacedCount} 处</span>
            <span className="variant-chip">{data.totalSamples} 条样本</span>
            <span className="panel__meta">
              同一规则下相同原值映射一致、不同原值不会合并，整数不会变成小数
            </span>
          </div>
          <div className="actions">
            <button type="button" className="btn btn--primary" onClick={copySamples}>
              {copied ? "✓ 已复制" : "复制匿名化样本"}
            </button>
            <button type="button" className="btn" onClick={() => setShowPreview((v) => !v)}>
              {showPreview ? "隐藏预览" : "预览匿名化样本"}
            </button>
          </div>
          {showPreview && (
            <pre className="schema-raw anonymize-preview">
              {JSON.stringify(data.samples, null, 2)}
            </pre>
          )}
        </>
      )}

      {!current && !invalidated && !error && (
        <div className="empty-hint">
          填写一条或多条 JSON Pointer 规则后点击「生成匿名化预览」：先查看各规则的命中数、
          未命中样本与错误，确认后再复制匿名化样本。非法 Pointer、命中对象 / 数组，
          或不同规则命中同一路径时会拒绝生成。
        </div>
      )}
    </div>
  );
}
