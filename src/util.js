/** True for a plain (non-null, non-array) object. Shared by the modules that
 *  validate untrusted JSON shapes (session, policy snapshot/publisher). */
export function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
