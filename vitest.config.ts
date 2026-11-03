import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations("./migrations"),
          ACCESS_TEAM_DOMAIN: "https://mate-test.cloudflareaccess.com",
          ACCESS_AUD: "mate-tests",
          ADMIN_EMAILS: "admin@example.com",
        },
      },
    })),
  ],
  test: {
    include: ["tests/**/*.test.ts"],
    setupFiles: ["./tests/setup.ts"],
    fileParallelism: false,
  },
});
