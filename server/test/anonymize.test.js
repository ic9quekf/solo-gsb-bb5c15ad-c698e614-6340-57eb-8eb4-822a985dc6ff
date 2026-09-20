"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const Ajv2020 = require("ajv/dist/2020").default;
const { anonymizeSamples, parsePattern, MAX_SAMPLES, MAX_RULES } = require("../anonymize");
const { inferSchema } = require("../infer");
const { createApp } = require("../app");

const USER_SAMPLES = [
  { id: 1, name: "Alice", email: "alice@example.com", age: 30, vip: true, phone: null },
  { id: 2, name: "Bob", email: "bob@example.com", age: 25, vip: false },
  { id: 3, name: "Alice", email: "alice@example.com", age: 41, vip: true },
];

/* ------------------------------ parsePattern ----------------------------- */

test("parsePattern unescapes RFC 6901 segments and marks '*' as wildcard", () => {
  assert.deepEqual(parsePattern(""), []);
  assert.deepEqual(parsePattern("/email"), ["email"]);
  assert.deepEqual(parsePattern("/a~0b"), ["a~b"]);
  assert.deepEqual(parsePattern("/a~1b"), ["a/b"]);
  const segments = parsePattern("/users/*/em~1ail");
  assert.equal(segments[0], "users");
  assert.equal(typeof segments[1], "symbol"); // the "*" wildcard marker
  assert.equal(segments[2], "em/ail");
  // Illegal: no leading slash, dangling or unknown "~" escapes, non-string.
  assert.equal(parsePattern("email"), null);
  assert.equal(parsePattern("*"), null);
  assert.equal(parsePattern("/a~2b"), null);
  assert.equal(parsePattern("/a~"), null);
  assert.equal(parsePattern(42), null);
  assert.equal(parsePattern(undefined), null);
});

/* ---------------------------- matching & stats ---------------------------- */

test("a literal pointer hits scalars across samples and reports misses", () => {
  const result = anonymizeSamples({ samples: USER_SAMPLES, rules: ["/email"] });
  assert.equal(result.totalSamples, 3);
  assert.equal(result.replacedCount, 3);
  assert.equal(result.rules.length, 1);
  const [rule] = result.rules;
  assert.equal(rule.index, 0);
  assert.equal(rule.pattern, "/email");
  assert.equal(rule.hits, 3);
  assert.equal(rule.distinctValues, 2); // alice appears twice
  assert.deepEqual(rule.missedSamples, []);

  const miss = anonymizeSamples({ samples: USER_SAMPLES, rules: ["/phone"] });
  assert.equal(miss.rules[0].hits, 1);
  assert.deepEqual(miss.rules[0].missedSamples, [1, 2]);

  const nowhere = anonymizeSamples({ samples: USER_SAMPLES, rules: ["/nope"] });
  assert.equal(nowhere.rules[0].hits, 0);
  assert.deepEqual(nowhere.rules[0].missedSamples, [0, 1, 2]);
  assert.equal(nowhere.replacedCount, 0);
});

test("the '*' wildcard matches object keys and array indices", () => {
  const samples = [
    { emails: { home: "a@x.io", work: "b@x.io" }, list: ["c@x.io", "d@x.io"] },
    { emails: { home: "a@x.io" }, list: ["e@x.io"] },
  ];
  const result = anonymizeSamples({ samples, rules: ["/emails/*", "/list/*"] });
  const [objects, arrays] = result.rules;
  assert.equal(objects.hits, 3);
  assert.deepEqual(objects.missedSamples, []);
  assert.equal(arrays.hits, 3);
  assert.deepEqual(arrays.missedSamples, []);
  // The shared value "a@x.io" is one distinct original under its own rule.
  assert.equal(objects.distinctValues, 2);
  assert.equal(arrays.distinctValues, 3);
  // Wildcard descent replaced the values in place, keeping the structure.
  assert.deepEqual(Object.keys(result.samples[0].emails), ["home", "work"]);
  assert.equal(typeof result.samples[0].emails.home, "string");
  assert.notEqual(result.samples[0].emails.home, "a@x.io");
  assert.equal(result.samples[0].emails.home, result.samples[1].emails.home);
});

test("wildcards combine with literal segments at any depth", () => {
  const samples = [
    { users: [{ name: "a", tags: ["x", "y"] }, { name: "b", tags: [] }] },
    { users: [{ name: "a" }] },
  ];
  const result = anonymizeSamples({ samples, rules: ["/users/*/name", "/users/0/tags/*"] });
  assert.equal(result.rules[0].hits, 3);
  assert.equal(result.rules[1].hits, 2);
  assert.deepEqual(result.rules[1].missedSamples, [1]);
  assert.equal(result.samples[0].users[0].name, result.samples[1].users[0].name);
  assert.notEqual(result.samples[0].users[0].name, "a");
  assert.equal(result.samples[0].users[0].tags.length, 2);
  assert.ok(result.samples[0].users[0].tags.every((t) => t.startsWith("anon_")));
});

test("numeric segments address array elements per RFC 6901", () => {
  const result = anonymizeSamples({
    samples: [{ list: ["keep", "hide", "keep2"] }],
    rules: ["/list/1"],
  });
  assert.equal(result.rules[0].hits, 1);
  assert.equal(result.samples[0].list[0], "keep");
  assert.notEqual(result.samples[0].list[1], "hide");
  assert.equal(result.samples[0].list[2], "keep2");
});

test("escaped segments address keys containing '~' and '/'", () => {
  const result = anonymizeSamples({
    samples: [{ "a~b": { "c/d": "secret" }, other: 1 }],
    rules: ["/a~0b/c~1d"],
  });
  assert.equal(result.rules[0].hits, 1);
  assert.notEqual(result.samples[0]["a~b"]["c/d"], "secret");
  assert.equal(result.samples[0].other, 1);
});

test("the empty pattern addresses the root (scalar samples)", () => {
  const result = anonymizeSamples({ samples: ["a", "a", "b"], rules: [""] });
  assert.equal(result.rules[0].hits, 3);
  assert.equal(result.rules[0].distinctValues, 2);
  assert.equal(result.samples[0], result.samples[1]);
  assert.notEqual(result.samples[0], "a");
  assert.notEqual(result.samples[2], "b");
  assert.notEqual(result.samples[0], result.samples[2]);
});

/* --------------------------- replacement rules --------------------------- */

test("replacements are stable across samples and never merge distinct values", () => {
  const result = anonymizeSamples({ samples: USER_SAMPLES, rules: ["/name", "/email"] });
  const [s1, s2, s3] = result.samples;
  // Same original under the same rule -> same replacement everywhere.
  assert.equal(s1.name, s3.name);
  assert.notEqual(s1.name, "Alice");
  assert.equal(s1.email, s3.email);
  // Different originals -> different replacements.
  assert.notEqual(s1.name, s2.name);
  assert.notEqual(s1.email, s2.email);
  // Untouched fields stay as they were.
  assert.deepEqual(
    result.samples.map((s) => s.id),
    [1, 2, 3]
  );
});

test("the mapping is deterministic across runs and isolated per rule", () => {
  const samples = [{ a: "same", b: "same" }];
  const first = anonymizeSamples({ samples, rules: ["/a", "/b"] });
  const second = anonymizeSamples({ samples, rules: ["/a", "/b"] });
  assert.deepEqual(first.samples, second.samples);
  // Different rules use independent mappings even for the same original.
  assert.notEqual(first.samples[0].a, first.samples[0].b);
});

test("JSON types are preserved: strings, integers, floats, booleans, null", () => {
  const samples = [
    { s: "x", i: 7, f: 1.5, b: true, n: null },
    { s: "y", i: -3, f: 2.5, b: false, n: null },
  ];
  const result = anonymizeSamples({ samples, rules: ["/s", "/i", "/f", "/b", "/n"] });
  for (const sample of result.samples) {
    assert.equal(typeof sample.s, "string");
    assert.ok(sample.s.startsWith("anon_"));
    assert.ok(Number.isInteger(sample.i)); // integers never become decimals
    assert.equal(typeof sample.f, "number");
    assert.ok(!Number.isInteger(sample.f)); // floats stay non-integer
    assert.equal(typeof sample.b, "boolean");
    assert.equal(sample.n, null);
  }
  // Distinct originals stay distinct, per type.
  assert.notEqual(result.samples[0].s, result.samples[1].s);
  assert.notEqual(result.samples[0].i, result.samples[1].i);
  assert.notEqual(result.samples[0].f, result.samples[1].f);
  // Booleans keep their exact value (no room for distinct boolean tokens).
  assert.equal(result.samples[0].b, true);
  assert.equal(result.samples[1].b, false);
});

test("many distinct integers map to many distinct integer replacements", () => {
  const samples = Array.from({ length: 100 }, (_, i) => ({ v: i - 50 }));
  const result = anonymizeSamples({ samples, rules: ["/v"] });
  const replacements = result.samples.map((s) => s.v);
  assert.ok(replacements.every((v) => Number.isInteger(v)));
  assert.equal(new Set(replacements).size, 100);
  assert.equal(result.rules[0].distinctValues, 100);
});

test("original samples are never mutated", () => {
  const samples = [{ name: "Alice", tags: ["x"] }];
  const before = JSON.stringify(samples);
  anonymizeSamples({ samples, rules: ["/name", "/tags/*"] });
  assert.equal(JSON.stringify(samples), before);
});

test("anonymized samples still validate against the inferred contract", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const { schema } = inferSchema(USER_SAMPLES);
  const validate = ajv.compile(schema);
  const result = anonymizeSamples({
    samples: USER_SAMPLES,
    rules: ["/name", "/email", "/age", "/vip", "/phone"],
  });
  for (const sample of result.samples) {
    assert.equal(validate(sample), true, JSON.stringify(validate.errors));
  }
});

/* ------------------------------- refusals -------------------------------- */

test("an illegal pointer refuses the export with 422 and per-rule errors", () => {
  for (const pattern of ["no-slash", "/a~2b", "/~"]) {
    assert.throws(
      () => anonymizeSamples({ samples: [{ a: 1 }], rules: ["/a", pattern] }),
      (err) => {
        assert.equal(err.status, 422);
        assert.match(err.message, /Pointer 非法/);
        assert.equal(err.details.rules.length, 2);
        assert.equal(err.details.rules[0].error, undefined);
        assert.equal(err.details.rules[0].hits, 1);
        assert.match(err.details.rules[1].error, /Pointer 非法/);
        assert.equal(err.details.rules[1].pattern, pattern);
        return true;
      }
    );
  }
});

test("hitting an object or an array refuses the export with positions", () => {
  assert.throws(
    () =>
      anonymizeSamples({
        samples: [{ address: { city: "x" }, tags: ["a"] }],
        rules: ["/address", "/tags"],
      }),
    (err) => {
      assert.equal(err.status, 422);
      assert.match(err.message, /对象或数组/);
      assert.equal(err.details.nonScalarHits.total, 2);
      const [objectHit, arrayHit] = err.details.nonScalarHits.entries;
      assert.deepEqual(
        { rule: objectHit.rule, sample: objectHit.sample, path: objectHit.path, type: objectHit.type },
        { rule: 0, sample: 0, path: "/address", type: "object" }
      );
      assert.equal(arrayHit.type, "array");
      assert.equal(arrayHit.path, "/tags");
      return true;
    }
  );
});

test("a wildcard hitting nested containers refuses as well", () => {
  assert.throws(
    () => anonymizeSamples({ samples: [{ a: { b: { c: 1 } } }], rules: ["/a/*"] }),
    (err) => {
      assert.equal(err.status, 422);
      assert.equal(err.details.nonScalarHits.entries[0].path, "/a/b");
      return true;
    }
  );
});

test("two rules claiming the same path refuse with conflict details", () => {
  assert.throws(
    () =>
      anonymizeSamples({
        samples: [{ user: { email: "a@x.io" }, id: 1 }, { user: { email: "b@x.io" }, id: 2 }],
        rules: ["/user/*", "/user/email", "/id"],
      }),
    (err) => {
      assert.equal(err.status, 422);
      assert.match(err.message, /同时命中/);
      assert.equal(err.details.conflicts.total, 2); // one per sample
      const [conflict] = err.details.conflicts.entries;
      assert.equal(conflict.sample, 0);
      assert.equal(conflict.path, "/user/email");
      assert.deepEqual(conflict.rules, [0, 1]);
      // The refusal still carries the per-rule statistics.
      assert.equal(err.details.rules[0].hits, 2);
      assert.equal(err.details.rules[2].hits, 2);
      return true;
    }
  );
});

test("duplicate rules conflict on every path they hit", () => {
  assert.throws(
    () => anonymizeSamples({ samples: [{ a: 1 }], rules: ["/a", "/a"] }),
    (err) => err.status === 422 && err.details.conflicts.total === 1
  );
  // Rules that hit nothing anywhere never conflict.
  const result = anonymizeSamples({ samples: [{ a: 1 }], rules: ["/zz", "/zz"] });
  assert.equal(result.replacedCount, 0);
});

test("input shape is validated with status 400", () => {
  for (const samples of [undefined, null, "nope", { 0: 1 }, []]) {
    assert.throws(
      () => anonymizeSamples({ samples, rules: ["/a"] }),
      (err) => err.status === 400 && /'samples' array/.test(err.message)
    );
  }
  assert.throws(
    () => anonymizeSamples({ samples: Array.from({ length: MAX_SAMPLES + 1 }, () => 1), rules: ["/a"] }),
    (err) => err.status === 400 && new RegExp(`${MAX_SAMPLES}`).test(err.message)
  );
  for (const rules of [undefined, null, "nope", []]) {
    assert.throws(
      () => anonymizeSamples({ samples: [{ a: 1 }], rules }),
      (err) => err.status === 400 && /'rules' array/.test(err.message)
    );
  }
  assert.throws(
    () => anonymizeSamples({ samples: [{ a: 1 }], rules: ["/a", 42] }),
    (err) => err.status === 400 && /string/.test(err.message)
  );
  assert.throws(
    () =>
      anonymizeSamples({
        samples: [{ a: 1 }],
        rules: Array.from({ length: MAX_RULES + 1 }, (_, i) => `/r${i}`),
      }),
    (err) => err.status === 400 && new RegExp(`${MAX_RULES}`).test(err.message)
  );
});

test("the 200-sample and 50-rule limits are inclusive", () => {
  const result = anonymizeSamples({
    samples: Array.from({ length: MAX_SAMPLES }, (_, i) => ({ v: i })),
    rules: ["/v"],
  });
  assert.equal(result.totalSamples, MAX_SAMPLES);
  assert.equal(result.replacedCount, MAX_SAMPLES);
});

/* ------------------------------ HTTP route ------------------------------- */

let server;
let base;

test.before(async () => {
  await new Promise((resolve) => {
    server = createApp().listen(0, "127.0.0.1", resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server.close());

async function post(pathname, body) {
  const res = await fetch(`${base}${pathname}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json() };
}

test("POST /api/anonymize returns anonymized samples with per-rule stats", async () => {
  const { status, data } = await post("/api/anonymize", {
    samples: USER_SAMPLES,
    rules: ["/name", "/email", "/missing"],
  });
  assert.equal(status, 200);
  assert.equal(data.totalSamples, 3);
  assert.equal(data.replacedCount, 6);
  assert.equal(data.rules.length, 3);
  assert.deepEqual(
    data.rules.map((r) => [r.pattern, r.hits, r.distinctValues]),
    [
      ["/name", 3, 2],
      ["/email", 3, 2],
      ["/missing", 0, 0],
    ]
  );
  assert.deepEqual(data.rules[2].missedSamples, [0, 1, 2]);
  // Originals are gone, structure and types are intact.
  assert.equal(JSON.stringify(data.samples).includes("Alice"), false);
  assert.equal(data.samples[0].name, data.samples[2].name);
  assert.equal(data.samples[1].vip, false);
});

test("POST /api/anonymize 422 response carries stats and offending positions", async () => {
  const { status, data } = await post("/api/anonymize", {
    samples: [{ user: { email: "a@x.io", name: "A" } }],
    rules: ["/user/*", "/user/email", "/oops~2"],
  });
  assert.equal(status, 422);
  assert.match(data.error, /已拒绝生成/);
  assert.equal(data.samples, undefined);
  // Per-rule stats: wildcard hit two scalars, the literal rule conflicts,
  // the last rule has an illegal pointer.
  assert.equal(data.rules[0].hits, 2);
  assert.equal(data.rules[1].hits, 1);
  assert.match(data.rules[2].error, /Pointer 非法/);
  assert.equal(data.conflicts.total, 1);
  assert.deepEqual(data.conflicts.entries[0].rules, [0, 1]);
  assert.equal(data.conflicts.entries[0].path, "/user/email");
});

test("POST /api/anonymize reports object/array hits with sample and path", async () => {
  const { status, data } = await post("/api/anonymize", {
    samples: [{ address: { city: "x" } }],
    rules: ["/address"],
  });
  assert.equal(status, 422);
  assert.match(data.error, /对象或数组/);
  assert.equal(data.nonScalarHits.total, 1);
  assert.deepEqual(data.nonScalarHits.entries[0], {
    rule: 0,
    pattern: "/address",
    sample: 0,
    path: "/address",
    type: "object",
  });
});

test("POST /api/anonymize validates its input", async () => {
  const missingSamples = await post("/api/anonymize", { rules: ["/a"] });
  assert.equal(missingSamples.status, 400);
  assert.match(missingSamples.data.error, /'samples' array/);

  const missingRules = await post("/api/anonymize", { samples: [{ a: 1 }] });
  assert.equal(missingRules.status, 400);
  assert.match(missingRules.data.error, /'rules' array/);

  const nonStringRule = await post("/api/anonymize", { samples: [{ a: 1 }], rules: [1] });
  assert.equal(nonStringRule.status, 400);
  assert.match(nonStringRule.data.error, /string/);

  const tooManySamples = await post("/api/anonymize", {
    samples: Array.from({ length: 201 }, () => 1),
    rules: ["/a"],
  });
  assert.equal(tooManySamples.status, 400);
  assert.match(tooManySamples.data.error, /200/);
});
