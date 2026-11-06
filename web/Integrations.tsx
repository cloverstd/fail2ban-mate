import { useState } from "react";
import type { IntegrationRow } from "./types";

export function Integrations({
  rows,
  busy,
  api,
  run,
  time,
}: {
  rows: IntegrationRow[];
  busy: boolean;
  api: <T = unknown>(
    path: string,
    body?: unknown,
    method?: string,
  ) => Promise<T>;
  run: (fn: () => Promise<unknown>, message?: string) => Promise<void>;
  time: (at: number | null) => string;
}) {
  const [name, setName] = useState("");
  const [token, setToken] = useState("");
  const [copyError, setCopyError] = useState(false);
  function issue(path: string, body?: { name: string }) {
    setToken("");
    setCopyError(false);
    void run(async () => {
      const issued = await api<{ token: string }>(path, body, "POST");
      setToken(issued.token);
      setName("");
    }, "Token 已生成");
  }
  return (
    <section className="panel integrations-panel">
      <form
        className="integration-actions"
        onSubmit={(event) => {
          event.preventDefault();
          issue("/integrations", { name: name.trim() });
        }}
      >
        <label>
          调用方名称
          <input
            required
            maxLength={80}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <button className="btn primary" disabled={busy || !name.trim()}>
          创建 Token
        </button>
      </form>
      {token && (
        <div
          className="integration-token"
          role="group"
          aria-label="新接入 Token"
        >
          <p>完整 Token 仅在此处显示一次。请保存到调用端的环境变量。</p>
          <code>{token}</code>
          <div className="integration-actions">
            <button
              className="btn small"
              onClick={() => {
                void navigator.clipboard.writeText(token).then(
                  () => setToken(""),
                  () => setCopyError(true),
                );
              }}
            >
              复制 Token
            </button>
            <button className="btn small" onClick={() => setToken("")}>
              关闭
            </button>
          </div>
          {copyError && (
            <p role="status">无法自动复制，请手动选中并复制 Token。</p>
          )}
        </div>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>调用方</th>
              <th>Token 前缀</th>
              <th>最近使用</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>
                  <code>{row.token_prefix}…</code>
                </td>
                <td>{time(row.last_used_at)}</td>
                <td>{row.revoked_at ? "已撤销" : "有效"}</td>
                <td>
                  {!row.revoked_at && (
                    <div className="integration-actions">
                      <button
                        className="text-btn"
                        disabled={busy}
                        onClick={() => {
                          if (
                            confirm(
                              "轮换后旧 Token 将立即失效，请更新调用端配置。",
                            )
                          )
                            issue(`/integrations/${row.id}/rotate`);
                        }}
                      >
                        轮换 Token
                      </button>
                      <button
                        className="text-btn danger"
                        disabled={busy}
                        onClick={() => {
                          if (
                            !confirm(
                              "撤销 Token 并移除该调用方的所有动态放行？",
                            )
                          )
                            return;
                          setToken("");
                          void run(
                            () =>
                              api(
                                `/integrations/${row.id}/revoke`,
                                undefined,
                                "POST",
                              ),
                            "Token 已撤销",
                          );
                        }}
                      >
                        撤销 Token
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && <p>暂无接入凭据</p>}
    </section>
  );
}
