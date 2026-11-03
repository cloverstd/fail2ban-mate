import { readFile, writeFile } from "node:fs/promises";
import { renderConfig } from "./deploy-config.mjs";
const config = renderConfig(
  await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
  process.env,
);
await writeFile(
  new URL("../wrangler.deploy.json", import.meta.url),
  JSON.stringify(config, null, 2) + "\n",
);
