# 协议与实现索引

## 仓库

`worker/`：Hono 路由、Access JWT 校验、D1 同步与 Durable Objects。`shared/protocol.ts`：云端和网页类型。`web/`：React 控制台与地图。`client/`：Go 客户端。`migrations/`：版本化 D1 迁移。`public/install.sh`：随 Worker 分发的安装器。

## 认证

管理 API 必须携带通过 Cloudflare Access 验证的 `Cf-Access-Jwt-Assertion`，签名、issuer、AUD、有效期和管理员邮箱均通过才能使用。写操作要求 Origin 与目标 origin 一致。后台 WebSocket 升级还要求同源，连接到 JWT 到期时关闭。

agent API 使用 `Authorization: Bearer <64 位十六进制 token>`。每个 token 对应一个节点，Worker 不信任客户端提供的 node ID。安装凭据通过 `POST /api/agent/v1/enroll` 交换，使用条件 UPDATE 原子消费；D1 仅存凭据哈希。

## Agent v1

Go 类型位于 `client/internal/mate/protocol.go`，服务端验证位于 `worker/validation.ts`。时间均为 Unix 秒。HTTP `POST /api/agent/v1/sync` 与 `GET /api/agent/v1/ws` 升级后的 JSON 消息使用相同协议。

`GET /api/agent/v1/addresses` 同样要求节点 token，仅使用 Cloudflare 的连接地址更新该节点的 `ipv4` 或 `ipv6`，返回本次观测的 `{ipv4,ipv6}`。它不接受客户端声明的 IP、不更新心跳和快照时间，也不清除另一地址族的历史记录。v0.1.1 客户端在独立后台任务中，启动时及每 5 分钟分别使用 `tcp4`、`tcp6` 探测；每次最多 5 秒，不跟随重定向，缺少任一地址族不影响同步。保留系统代理配置，使用代理时记录实际到达控制端的出口地址。

客户端发送 `protocol: 1`、`type: "sync"`，以及：

| 字段                              | 含义                                                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `sequence`                        | 本次消息涵盖的最大顺序号，不得跳过尚未发送的事件；携带全量快照时可覆盖旧状态                                 |
| `events`                          | 最多 100 个 `{id,seq,kind,jail,ip,observed_at,country?,city?,latitude?,longitude?}`                          |
| `snapshot`                        | 可选的 `{seq,jails:[{name,bans:[]}],unavailable_jails:[]}`；成功读到的 jail 是权威快照，失败 jail 保留旧状态 |
| `results`                         | 最多 100 个命令结果 `{id,status,error?}`                                                                     |
| `applied_config_revision`         | 已采用的节点配置版本                                                                                         |
| `applied_policy_revision`         | 已应用的全局白名单版本                                                                                       |
| `actual_mode` / `fallback_reason` | 当前传输方式及自动降级原因                                                                                   |
| `version` / `error`               | 客户端版本与采集/白名单错误                                                                                  |

服务端提交 D1 后返回：

- `config: {revision,mode,poll_interval}`：节点期望配置。
- `policy_revision`、`policies: [{id,ip,expires_at}]`：当前有效全局规则，`expires_at: null` 为永久。
- `commands: [{id,kind,jail,ip,expires_at}]`：待确认的 ban/unban 命令，未确认会重复下发。
- `ack_event_ids`、`ack_result_ids`、`ack_snapshot_seq`：仅确认已持久化的数据；客户端收到后才移除队列或推进快照周期。
- `snapshot_required`：控制端尚无已观测快照，请客户端上报。
- `server_time`：用于发现不安全的系统时钟偏差。

每个节点通过同一个 Durable Object 串行处理 HTTP 和 WebSocket。事件 ID 去重；旧顺序号重传只补历史，不覆盖更新的当前状态。重连快照可以修正本机执行命令、短暂断线等造成的状态差异。没有原始封禁时间的记录保留观测时间。

## 管理接口

| 方法和路径（前缀 `/api/admin`） | 输入 / 输出                                               |
| ------------------------------- | --------------------------------------------------------- |
| `GET /dashboard`                | 节点、当前封禁、有效全局规则、最近命令与审计              |
| `GET /ws`                       | 认证后升级，收到 `{"type":"invalidate"}` 时刷新           |
| `POST /nodes`                   | `{name}` → `{id,enrollment,expires_at}`                   |
| `PATCH /nodes/:id`              | 可选 `{name,enabled,mode,poll_interval}`                  |
| `POST /nodes/:id/enrollment`    | 撤销旧 token，生成新一次性凭据                            |
| `POST /nodes/:id/revoke`        | 撤销长期 token 和未使用凭据                               |
| `DELETE /nodes/:id`             | 删除节点及其关联状态、事件和命令                          |
| `POST /commands`                | 最多 100 个 `{node_id,kind,jail,ip}`，返回命令 ID         |
| `POST /whitelist`               | `{ip,duration}`，duration 为秒或 null；按 IP 更新全局规则 |
| `DELETE /whitelist/:id`         | 撤销规则并递增全局版本                                    |

公共接口 `GET /api/public/dashboard` 只返回显式挑选和脱敏后的字段。禁止把管理对象整体序列化到公开端，包括错误、审计、节点名称和各种 token 哈希。

## 发布兼容

协议只接受版本 1；升级时保持旧字段语义，新增可选字段优先。D1 迁移先部署，必须兼容仍在运行的上一版 Worker。客户端配置和状态放在独立目录，升级仅替换二进制并重启服务。
