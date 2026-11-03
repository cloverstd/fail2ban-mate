import { env, applyD1Migrations } from "cloudflare:test";
import type { D1Migration } from "@cloudflare/vitest-plugin";
import type { Env as WorkerEnv } from "../worker/env";
declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
