import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

test("history migration recovers completed periods and preserves current bans", () => {
  const db = new DatabaseSync(":memory:");
  const migration = (name) =>
    readFileSync(new URL(`../migrations/${name}`, import.meta.url), "utf8");
  try {
    db.exec(migration("0001_initial.sql"));
    db.exec(migration("0002_node_addresses.sql"));
    db.exec(
      "INSERT INTO nodes(id,name,created_at,observed_at) VALUES('node','test',1,900)",
    );
    const event = db.prepare(
      "INSERT INTO events(id,node_id,seq,kind,jail,ip,observed_at,received_at) VALUES(?,'node',?,?,'sshd',?,?,1000)",
    );
    event.run("first", 1, "ban", "203.0.113.1", 100);
    event.run("release", 2, "unban", "203.0.113.1", 200);
    event.run("reban", 3, "ban", "203.0.113.1", 300);
    event.run("snapshot-removed", 4, "ban", "203.0.113.2", 400);
    // Sequence still separates distinct periods with identical timestamps.
    event.run("same-second-ban", 5, "ban", "203.0.113.3", 500);
    event.run("same-second-unban", 6, "unban", "203.0.113.3", 500);
    event.run("same-second-reban", 7, "ban", "203.0.113.3", 500);
    db.exec(
      "INSERT INTO bans(node_id,jail,ip,observed_at) VALUES('node','sshd','203.0.113.1',300),('node','sshd','203.0.113.3',500),('node','sshd','203.0.113.4',600)",
    );
    db.exec(migration("0003_ban_history.sql"));
    const periods = db
      .prepare(
        "SELECT id,observed_at,unbanned_at FROM ban_history ORDER BY observed_at",
      )
      .all()
      .map((row) => ({ ...row }));
    assert.deepEqual(periods, [
      { id: "event:first", observed_at: 100, unbanned_at: 200 },
      { id: "event:snapshot-removed", observed_at: 400, unbanned_at: 900 },
      { id: "event:same-second-ban", observed_at: 500, unbanned_at: 500 },
    ]);
    assert.equal(db.prepare("SELECT count(*) n FROM bans").get().n, 3);
    db.exec("DELETE FROM nodes WHERE id='node'");
    assert.equal(db.prepare("SELECT count(*) n FROM ban_history").get().n, 0);
  } finally {
    db.close();
  }
});
