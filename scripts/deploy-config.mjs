import { parse, printParseErrorCode } from "jsonc-parser";
export function renderConfig(source, variables) {
  const errors = [];
  const config = parse(source, errors, { allowTrailingComma: true });
  if (errors.length)
    throw new Error(
      "Invalid Wrangler JSONC: " + printParseErrorCode(errors[0].error),
    );
  // Account-specific, non-secret defaults live in Wrangler; build variables can
  // override them for another deployment. Never synthesize Access identity.
  const inputs = {
    D1_DATABASE_ID: config.d1_databases?.[0]?.database_id,
    ACCESS_TEAM_DOMAIN: config.vars?.ACCESS_TEAM_DOMAIN,
    ACCESS_AUD: config.vars?.ACCESS_AUD,
    ADMIN_EMAILS: config.vars?.ADMIN_EMAILS,
    ...Object.fromEntries(
      Object.entries(variables).filter(([, v]) => v !== undefined),
    ),
  };
  const required = [
    "D1_DATABASE_ID",
    "ACCESS_TEAM_DOMAIN",
    "ACCESS_AUD",
    "ADMIN_EMAILS",
  ];
  for (const key of required)
    if (!inputs[key]) throw new Error(`Missing deployment variable: ${key}`);
  if (
    !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(inputs.D1_DATABASE_ID)
  )
    throw new Error("D1_DATABASE_ID must be a UUID");
  if (inputs.D1_DATABASE_ID === "00000000-0000-0000-0000-000000000000")
    throw new Error("D1_DATABASE_ID is an unconfigured placeholder");
  config.d1_databases[0].database_id = inputs.D1_DATABASE_ID;
  for (const key of ["ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "ADMIN_EMAILS"])
    config.vars[key] = inputs[key];
  if (inputs.WORKER_DOMAIN) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(inputs.WORKER_DOMAIN))
      throw new Error("WORKER_DOMAIN must be a hostname");
    config.routes = [{ pattern: inputs.WORKER_DOMAIN, custom_domain: true }];
  }
  return config;
}
