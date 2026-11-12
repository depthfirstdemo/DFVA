import assert from "node:assert/strict";
import { test } from "node:test";
import { api } from "./routes";
import { insertUserSchema } from "./schema";

test("Zod 4 keeps previously optional any-valued response fields optional", () => {
  const cases = [
    [api.tools.deserialize.responses[200], "result", {}],
    [api.tools.debugInfo.responses[200], "env", {}],
    [api.tools.bypassAuth.responses[200], "stats", {}],
    [api.tools.calculateDiscount.responses[200], "breakdown", { finalAmount: 10 }],
  ] as const;

  for (const [schema, field, input] of cases) {
    const output = schema.parse(input);
    assert.equal(Object.hasOwn(output, field), false);
    assert.deepEqual(schema.parse({ ...input, [field]: null }), { ...input, [field]: null });
  }
});

test("Drizzle insert schemas still parse through the Zod 4 integration", () => {
  assert.equal(insertUserSchema.parse({ username: "alice", password: "secret" }).username, "alice");
});
