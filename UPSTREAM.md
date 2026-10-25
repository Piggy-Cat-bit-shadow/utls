# 上游关系（UPSTREAM）

此文件是本仓库与上游关系的**唯一权威说明**，供后续维护者与 AI Agent 直接读取。

## 机器可读字段

```text
PRIMARY_UPSTREAM_REPO = MetaCubeX/utls
PRIMARY_UPSTREAM_BRANCH = v1.9.0-mod-meta
DEVELOPMENT_BRANCH = main
UPSTREAM_MIRROR_BRANCH = mirror/meta-v1.9.0
LEGACY_DEFAULT_BRANCH = v1.7.0-mod-meta (NOT TRACKED)
UPSTREAM_SYNC_RULE = Sync 1.9 mirror, merge into main, validate, then update consumer pins only when necessary.
```

## 中文说明

### 只跟踪一条上游

- 唯一日常跟踪的直接上游：`MetaCubeX/utls` 的 **`v1.9.0-mod-meta`**。
- `v1.7.0-mod-meta` 是对方仓库的**默认分支**，不是本仓库的更新目标：不建 1.7 镜像、不把 1.7 的独有提交并入 `main`、不用 `git merge -s ours` 伪造 1.7 祖先。
- `refraction-networking/utls` 是上上游，本仓库不跟踪、不审计、不合并。

### 分支

- **`main`**：唯一正式开发 / 默认分支，承载上游 1.9 与本 fork 的自定义提交。
- **`mirror/meta-v1.9.0`**：纯上游镜像。HEAD 必须与 `MetaCubeX/utls:v1.9.0-mod-meta` 的 HEAD **严格相等**，不混入任何自定义提交；同步只允许快进，禁止 force push 覆盖他人工作。
- 历史 tag（`archive/*`、`utls-hybrid-v1`、`v1.6.*` 等）保留，作为旧版本回退点，不删除、不移动。

### 同步流程（每次升级都照此执行）

1. `git fetch upstream --prune --tags`，读取 `upstream/v1.9.0-mod-meta` 的**实时** HEAD（不要用文档里的旧 SHA）。
2. 把 `mirror/meta-v1.9.0` 快进到该 HEAD（`git merge --ff-only`），推送。
3. 在 `main` 上比较 `behind`：为 0 时**不做任何合并**；有新增提交时正常 `git merge`（保留历史），逐项审计冲突，确认自定义行为全部保留后跑回归。
4. 只有在**生产代码实际变化且验收通过**时，才更新消费方 pin；纯文档、镜像分支、无内容变化的祖先整理都**不更新** pin（不要为了新 HEAD 去造伪版本）。

### 不得回退的能力（每次升级都必须回归）

- Firefox 148 / Safari 26.3 混合密钥交换（自定义提交 `6c3e08ed4c4dd43741d4e55f54eb404cd33ad2fa`），以及对应的 hello 回归测试。
- REALITY 相关修复（服务端证书懒初始化、REALITY 目标 TLS record buffer 16 KiB 等）。
- HTTP/3 / QUIC：`UQUICConn` 与 `QUICConn` 行为同步、`SetTransportParameters` 能到达预设 ClientHello、QUIC close 回归测试。
- `main` 优先保留本 fork 的自定义实现；上游实现只有在等价、或经回归证明更好时才替换。

### 消费方 pin

- `sing-box` 根 `go.mod` 与 `test/go.mod` 的 `replace github.com/metacubex/utls` 必须**同时**指向本 fork，且两处**完全一致**。
- 截至 2026-10-25 两处均为 `v1.8.8-0.20261025000922-e4448e857e07`（对应提交 `e4448e857e07`）。
- 更新前提：本仓库生产代码有实际变更且回归通过，然后两处一起改、一起验证消费者核心 CI；本文件这类文档提交不构成改 pin 的理由。

### GitHub 页面的 Ahead/Behind

GitHub Fork 页面的 Ahead/Behind 指示器按**父仓库默认分支 `v1.7.0-mod-meta`** 计算，与本仓库实际跟踪的 1.9 无关。看到 "behind 1.7" 属正常现象，**不得**为了改这个数字而合并无关历史、rebase 或改写已发布历史。
