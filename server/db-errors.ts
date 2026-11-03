import { DrizzleQueryError } from "drizzle-orm";

/** Drizzle wraps PostgreSQL errors; the original constraint details live in cause. */
export function isUniqueConstraintError(error: unknown): boolean {
  const cause = error instanceof DrizzleQueryError ? error.cause : error;
  return (cause instanceof Error && cause.message.includes("unique")) ||
    (typeof cause === "object" && cause !== null && "code" in cause && cause.code === "23505");
}
