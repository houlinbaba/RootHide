# D1 生效条件及剩余能力边界

本轮仅编译／研究，不操作设备、不提供安装包。D1 是诊断候选，F1/F3 仍 FAIL。

## 诊断语义复核

对照 39c2d31：`dopamine_domain_allowed` 保留相同路径检查及 bundle 判断；get-root 保留目标查找、身份检查、路径错误转换和 credential_install 调用。所有原有返回值与短路顺序保留。credential_read_bytes 只在原先 kreadbuf→EIO 转换前记 raw；原写入、引用、发布判断、回滚顺序及原返回表达式未改。首次错误在回滚／close／reap 前保存，不将回滚失败覆盖为首错，也不宣称回滚一定完成。

rh_failure_begin/note 只操作同步线程本地 scope，不调用权限接口；end 在日志前保存 errno，日志后恢复。新增 App/RPC 日志使用既有会保存 errno 的 stage logger。授权消费仍逐 token 执行，服务端失败、协议错误与本地消费失败分别记录。22 项 credential/get-root、11 项服务端、9 项客户端及 8 请求交错检查与 4 个破坏变体均在宿主复核；这是诊断契约证据，不是 Apple 或设备证据。

## 版本必须分四层

| 层 | 可靠记录 | 不能据此推断 |
| --- | --- | --- |
| App | 本次精确构建 SHA、Info.plist 版本、Dopamine Mach-O UUID | 运行中的 launchd 已更换 |
| App 内的 libjailbreak | 包内 Mach-O UUID，检查新增符号与诊断格式 | 系统服务实际加载这份 dylib |
| 包内 basebin | libjailbreak／launchdhook／boomerang／jailbreakd／jbctl 各架构 UUID、SHA256、依赖及归档成员一致性 | `.version=3.0.7` 能区分所有修订，或运行中组件就是磁盘上这份文件 |
| 设备实际加载 | 与服务 PID／启动会话对应的**已映射 image UUID**及新请求产生的服务端阶段记录 | 只看 App SHA、路径、磁盘哈希、启动时间或 `.version` 即证明已加载 |

Apple 检查脚本生成前三层文本清单，并验证实际导出／导入及包内文件。第四层本轮为 **未知／未验证**；新 get-root/check-in 服务端代码属于 launchdhook，底层诊断属于 libjailbreak。仅换 App 最多更新客户端，旧 launchd 不会凭空输出新服务端首错。

## 将来部署前的方案（尚未执行）

1. 先取得当前设备会话和实际映射的 launchdhook、libjailbreak UUID。现有导出不足时，先完成只读用户态映像身份采集并单独检查；不通过读取文件冒充映像身份，不为取证制造崩溃。
2. 只换 App 无法激活旧服务中的代码。更换已加载组件需要规划新的越狱会话或正式更新切换。当前 F3 仍 FAIL，不通过用户空间重启强行激活诊断，也不在现有会话里热替换服务。
3. 若后续选择整机重启后用精确 SHA 重新越狱：须先准备已验证的旧版本回退、保留旧包及日志，说明越狱会话丢失／重新越狱失败风险并由用户确认；新会话仍须核对实际映像 UUID。若 UUID 不符或服务状态异常，停止取证，不继续触发重启／安装插件；回退使用预备的已验证版本并重新建立会话。具体设备与系统适用性尚未验证，本轮不执行此步骤。
4. 实际取证动作限定为 App check-in／授权、get-root、空操作和身份恢复。可复用 runAsRoot 的序列化和 finally 恢复语义，但**目前没有已验证的独立诊断入口**；在设备阶段前需要补好并证明不会调用 spawnJbctlAsRootWithArgs、jbctl、rebootUserspace 或 SpringBoard 重启。失败保留原返回与恢复失败退出行为，不吞错。
5. 失败包必须包含同一请求的 App rpc_result／消费阶段、服务端 authorize／get_root 首错、raw/domain/converted、恢复结果及各映像身份。日志无新元数据时先判定覆盖／加载证据不足，不能猜错误 5 的来源。drop-root 目前保留既有返回及 App 恢复结果日志，未增加独立的服务端首错 scope；若问题落在恢复阶段，须单独补齐此诊断缺口。

## F1 本阶段收敛结论

- **现有可保证**：传输等待和本地 worker 容量有界；超时仍保留在途请求／worker 引用；服务端在 callback 前后核对期限和 pidversion；已报告的本地／远端错误不应被转换为成功。
- **无法保证**：本地超时不等于远端停止；PID 复核与后续信号不原子；无已验证的目标持有、取消完成栅栏、未知结果终态查询、部分 patch 回滚或安全的失联最终处置。
- **安全的最小推进**：保留既有有界传输及在途引用；准确区分未发送、已知失败、结果未知，不把未知当成功或已取消。涉及最终 kill／resume 的产品改动仍须先有身份和生命周期依据。本轮不修改这些路径，不宣称已经安全。
- **支持边界**：固定 XNU 10002.1.13 的 proc_find_ident 等证据只作该版本参考。用户态现有 proc_find／proc_rele 不提供相应计数引用语义。本阶段不新增内核桥、不扩大授权、不引入未经验证的引用操控。未知结果后的目标处置路径仍不得宣称安全，F1 保持 FAIL。
