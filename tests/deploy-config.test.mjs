import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderConfig } from "../scripts/deploy-config.mjs";
const source = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8",
);
const variables = {
  D1_DATABASE_ID: "12345678-abcd-abcd-abcd-123456789012",
  ACCESS_TEAM_DOMAIN: "https://test.cloudflareaccess.com",
  ACCESS_AUD: "test-aud",
  ADMIN_EMAILS: "admin@example.com",
};
test("reads Wrangler JSONC including comments and trailing commas", () => {
  const config = renderConfig("// test\n" + source, variables);
  assert.equal(config.d1_databases[0].database_id, variables.D1_DATABASE_ID);
  assert.equal(config.vars.ACCESS_AUD, "test-aud");
  assert.equal(config.durable_objects.bindings.length, 2);
  assert.equal(config.routes, undefined);
});
test("rejects missing deployment identity and invalid hostname", () => {
  assert.throws(
    () => renderConfig(source, { ...variables, ACCESS_AUD: "" }),
    /ACCESS_AUD/,
  );
  assert.throws(
    () =>
      renderConfig(source, {
        ...variables,
        WORKER_DOMAIN: "https://example.com",
      }),
    /hostname/,
  );
  assert.equal(
    renderConfig(source, { ...variables, WORKER_DOMAIN: "ban.example.com" })
      .routes[0].custom_domain,
    true,
  );
});
