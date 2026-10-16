# F3 交接设计与最小纠正（实施前，2026-10-16）

适用基线：39c2d31；整改前候选：5337b52。此页定义本轮支持边界，不承诺 F3 闭合。

| 阶段／承诺 | 目标、端口及资源负责人 | 失败边界 |
| --- | --- | --- |
| 获取 primitives、登记 helper、发送 DONE | helper 持有 primitives 和接收端口；旧 launchd 持有其登记的 helper 发送权；旧 launchd 的独立接收队列处理 RPC | DONE 前旧 launchd 可拒绝 SETEXEC，并请求终止 helper；登记后失败的端口清理仍有历史缺口 |
| DONE 后更新 basebin | DONE **仅表示 primitives 已取得且 helper 已登记**，不表示目标暂停、patch 完成或服务 READY。旧 launchd 仍运行并负责更新；helper 等待 PID 1 暂停 | 更新／调度无已证明的 10 秒上界；helper 此时自行超时退出无法撤销旧 launchd 的成功返回 |
| 切换准备与 SETEXEC | 旧 launchd 发起原 spawn wrapper；成功执行 SETEXEC 是不可逆边界，旧映像不再有恢复职责的执行能力 | 已有代码没有 DONE 后故障通知与切换提交的原子屏障；再查存活或增一个 ACK 不能消除此窗口 |
| 新目标暂停、准备、patch | helper 查询 PID 1 暂停、等待初始化、再次确认暂停，再同步 patch；callback 返回前不释放其使用的资源，不并发取消 | 查询／准备／callback 失败不恢复目标；该架构不能保证切换后恢复旧 launchd，也不能证明部分 patch 回滚 |
| SIGCONT、服务 READY、最终 DONE | helper 检查 SIGCONT；成功后进入 dispatch_main，新 launchd 从登记端口取回 primitives，清登记槽并发送最终 DONE；helper 随后退出 | SIGCONT 失败真实上报；新服务无法启动时没有安全回滚保证。最终 DONE 只对应成功回收路径，不能覆盖此前故障 |
| jailbreakd 的 START_SUSPENDED 子进程 | 父进程拥有新子进程及 attributes，完成 patch 后负责恢复；失败调用既有清理 | SIGKILL 失败或延迟回收耗尽仍为历史缺口；不能以“已返回错误”声称资源全部回收 |

**本轮最小实现**：撤去 cd16751 新增的统一准备期限及其时钟依赖；保留 100ms 准备等待错误、暂停复核、同步 callback 错误及 SIGCONT 错误传播。两调用方恢复允许正常迟到准备，避免同一公共函数留下另一条同源回归。不是延长期限，也不改 DONE／授权／切换协议。

**真实承诺**：不会仅因正常更新／调度超过 10 秒而退出；保留已观测错误传播。恢复基线的无界暂停等待是明确未解决项；没有可证明安全的有限失联处置，不称为完整修复。不得将 helper 失败后的登记槽、暂停目标或 primitives 视为已清理。

**验收与隔离**：同一调用方夹具执行审计基线、原候选和纠正版本，保留正确性断言；故障注入与目标可达性分列。跨组件 FAIL 继续阻止修复候选资格。CI 仅上传文本编译／组件证据，禁止上传 TIPA／IPA／basebin 或运行库，且打包入口拒绝无显式研究标记的构建。本轮无设备操作。
