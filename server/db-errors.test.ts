import { strict as assert } from "node:assert";
import { test } from "node:test";
import { DrizzleQueryError, sql } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";
import { isUniqueConstraintError } from "./db-errors";

test("detects a PostgreSQL unique violation wrapped by Drizzle", () => {
  const cause = Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });
  assert.equal(isUniqueConstraintError(new DrizzleQueryError("insert into kb_articles ...", [], cause)), true);
  assert.equal(isUniqueConstraintError(new DrizzleQueryError("insert ...", [], Object.assign(new Error("duplicate"), { code: "23505" }))), true);
});

test("does not confuse the query text with an underlying unique violation", () => {
  assert.equal(isUniqueConstraintError(new DrizzleQueryError("insert into unique_articles ...", [], new Error("connection closed"))), false);
  assert.equal(isUniqueConstraintError(new Error("unique constraint failed")), true);
  assert.equal(isUniqueConstraintError(new Error("connection closed")), false);
});


test("escapes embedded quotes in PostgreSQL identifiers", () => {
  const query = new PgDialect().sqlToQuery(sql`select ${sql.identifier('name"; drop table users; --')}`);
  assert.equal(query.sql, 'select "name""; drop table users; --"');
  assert.deepEqual(query.params, []);
});
