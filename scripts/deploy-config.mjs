import { parse, printParseErrorCode } from "jsonc-parser";
export function renderConfig(source, variables) {
  const required = [
    "D1_DATABASE_ID",
    "ACCESS_TEAM_DOMAIN",
    "ACCESS_AUD",
    "ADMIN_EMAILS",
  ];
  for (const key of required)
    if (!variables[key]) throw new Error(`Missing repository variable: ${key}`);
  if (
    !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(
      variables.D1_DATABASE_ID,
    )
  )
    throw new Error("D1_DATABASE_ID must be a UUID");
  const errors = [];
  const config = parse(source, errors, { allowTrailingComma: true });
  if (errors.length)
    throw new Error(
      "Invalid Wrangler JSONC: " + printParseErrorCode(errors[0].error),
    );
  config.d1_databases[0].database_id = variables.D1_DATABASE_ID;
  for (const key of ["ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "ADMIN_EMAILS"])
    config.vars[key] = variables[key];
  if (variables.WORKER_DOMAIN) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(variables.WORKER_DOMAIN))
      throw new Error("WORKER_DOMAIN must be a hostname");
    config.routes = [{ pattern: variables.WORKER_DOMAIN, custom_domain: true }];
  }
  return config;
}
