import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";

test("public HTML and scripts contain no administration URLs", async () => {
  const root = new URL("../dist/", import.meta.url);
  const files = [
    "index.html",
    ...(await readdir(new URL("assets/", root)))
      .filter((name) => name.endsWith(".js"))
      .map((name) => "assets/" + name),
  ];
  for (const file of files) {
    assert.doesNotMatch(
      await readFile(new URL(file, root), "utf8"),
      /\/(?:api\/)?admin(?:[\/"'`?]|$)/,
      file,
    );
  }
  const privateHtml = await readFile(new URL("admin/index.html", root), "utf8");
  assert.match(privateHtml, /src="\/admin\/assets\//);
});
