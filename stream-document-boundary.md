# 流式解析的文档边界判定分析（document_stream / parse_many / iterate_many）

代码基线：分支 `task/67`，HEAD `449f38e`。
实测方法：`/tmp/stream_probe/probe*.cpp`，直接编译仓库当前 `include/` + `src/simdjson.cpp`（未用陈旧的 singleheader），
对照单文档入口 `parser.iterate()` 与流式入口 `parser.iterate_many()`（ondemand）/ `parser.parse_many()`（DOM），
batch_size 取 32/64，记录每个文档的起始偏移、消费结果、流错误与 `truncated_bytes()`。

## 1. 边界判定的责任分工

| 层 | 位置 | 职责 |
|---|---|---|
| stage1 结构索引 | `src/generic/stage1/json_structural_indexer.h:265` `finish()` | 产出结构字符索引；`streaming_partial` 容忍未闭合字符串并丢弃其起始引号（`:322-329`）；`streaming_final` 截断尾部不完整文档（`:350-375`）；写哨兵 `idx[n]=idx[n+1]=len`（`:295-297`） |
| 批边界选择 | `src/generic/stage1/find_next_document_index.h:60` | 从批尾倒扫，找"最后一个完整文档"的结束位置；`ends_with_partial_scalar`（`:39`）与 `ends_with_unfinished_document`（`:55`）把"可能被下一批继续"的尾部留到下一批 |
| 无效尾部防护 | `include/simdjson/generic/ondemand/document_stream-inl.h:448` `end_batch_before_invalid_tail()` | 若批尾下一字节是 `, : ] }` 或批尾最后是 `, : [ {`，用 `stream_documents_are_well_formed()`（`:406`）校验尾部；不合法则截短本批（或整批无效时 TAPE_ERROR），防止 On-Demand 把下一批读成当前文档的值 |
| 流驱动 | `document_stream-inl.h:250` `next()` / `:400` `next_batch_start()` | 跨批推进、重锚 `json_iterator`；`next_batch_start = batch_start + idx[n]` |
| 分隔符快进 | `document_stream-inl.h:328` `skip_to_delimiter()` / `:357` `next_document()` | 仅 ndjson / json_sequence 模式：`memchr` 找 `\n`/`0x1E` 并跳过当前文档未读部分，**不做结构校验**（代码注释 `:371-376` 明确承认） |
| 截断报告 | `document_stream-inl.h:140`（ondemand）/ `include/simdjson/dom/document_stream-inl.h:315`（DOM）`truncated_bytes()` | CAPACITY 时返回 `len - batch_start`；否则返回 `idx[n] - idx[n+1]`，依赖 streaming_final 的哨兵约定 |
| 调用方 | 用户代码 | 必须消费（读取）每个文档才触发 ondemand 的惰性校验；必须在流结束后检查 `truncated_bytes()` |

## 2. 实测记录

### 2.1 合法跨批续读（判定正确，与单文档入口一致）

batch=64，前置 31 字节文档使目标文档跨越字节 64 边界：

| 用例 | 输入形态 | 结果 |
|---|---|---|
| string_cross | `{"a":"…40 x…"}` 跨边界 | 3 文档，`raw_json` 与单文档完全一致，truncated=0 |
| number_cross | `{"k":777…}` 数字跨边界 | 同上，数值未被拆成两个文档 |
| container_cross | `[1,…,15]` 跨边界 | 同上 |
| valid_straddle | `[1,` 在批尾 + `2]` 在下批 | 批 1 推迟（defer），批 2 重读得 `[1,2]`，后续 `3` 为独立文档 |
| ws_run | 两数字间 200 空格（含整批空白） | 2 文档，threaded=0/1 一致 |
| bracket_next_batch | 下批以 `[2]` 开始 | 不会被并入上批，2 文档 |

机制：批尾若是未闭合字符串/未闭合容器/半个标量，stage1 丢弃尾部结构索引，下一批从被推迟的字节重扫——**跨批续读靠"重读"而非"拼接"实现，下一批内容不会被误认作当前文档的值**。

### 2.2 超长文档（拒绝行为正确）

| 用例 | 结果 |
|---|---|
| 单文档 78B > batch 64（字符串/数字/数组） | ondemand 与 DOM 均 `CAPACITY`，流中止，`truncated_bytes = len - batch_start`（如 78、208），与 `document_stream-inl.h:144` 一致 |
| ndjson 长行 / json_sequence 长记录 | 同样 CAPACITY；ondemand json_sequence 下 `truncated_bytes=89=len` 正确 |

### 2.3 可利用/易误用的边界混淆

**(P1) ndjson/json_seq 下"未消费的多行文档"被拆分，余部被当作独立文档（文档伪造）**

输入 `{"a":\n1}\n{"b":2}\n`（2 个文档），调用方不消费 doc0（计数/过滤场景极常见）：

```
doc[0] @0 非标量，未消费
doc[1] @6 标量 get_double=1        ← 伪造文档：原文档的残余 "1"
doc[2] @7 标量 "}"                 ← 伪造文档
doc[3] @9 {"b":2}
=> 产出 4 个文档（实际 2 个）
```

对照：同一输入若**完全消费** doc0，则正确产出 2 文档；ws 模式（无分隔符快进）不消费也正确（2 文档）。
根因：`next_document()` 在 `depth()>0` 时用 `skip_to_delimiter()` 直接 `memchr` 到第一个 `\n`，
而该 `\n` 在文档内部（字符串或结构里）。`document_stream-inl.h:371-376` 的注释承认
"Callers that leave depth() > 0 while violating that contract … can mis-align following documents"。
输入确实违反了"一行一文档"约定，但失败模式是**静默地产出额外"合法"文档**（`1` 可通过 get_double 验证），
下游按文档计数/转发时会注入攻击者可控的标量文档。json_sequence 模式同理（分隔符 0x1E）。

**(P2) 垃圾字节作为"文档"交付，ondemand 不消费则不报错**

ws 模式 `{"a":1} xyz`：ondemand 产出 2 个"文档"且 `doc.error()==SUCCESS`；DOM 对 `xyz` 立即 TAPE_ERROR。
单发实测：`xyz`、`,`、`]` 的 `type()` 均返回 SUCCESS（type=unknown=0），只有具体 getter 才报错
（`12x` → get_double NUMBER_ERROR；`tru` → get_bool INCORRECT_TYPE）。
批边界变体：`{"a":1}` + 填充 + `,{"b":2}`（下批以 `,` 开头）→ ondemand 把 `,` 交付为文档且消费"成功"，
下一迭代才报 INCOMPLETE_ARRAY_OR_OBJECT；DOM 立即 TAPE_ERROR。
结论：**ondemand 流的文档数不等于有效文档数**；只检查 `!doc.error()` 的调用方会接受非 JSON 内容。

**(P3) 最终批静默截断**

`{"a":1} {"b":` → 1 个文档、无错误、`truncated_bytes=5`；`{"a":"abc`（未闭合字符串）→ 0 文档、无错误、`truncated_bytes=9`。
这是设计行为（`json_structural_indexer.h:353-360` 注释：允许截断的下载流），但**唯一信号是 `truncated_bytes()`**，
不检查的调用方会把截断流当成功处理。

**(P4) `truncated_bytes()` 在部分错误路径返回垃圾值**

DOM ws 流输入含 0x1E 字节（89B，batch=64）：流以 TAPE_ERROR 结束后 `truncated_bytes()=4294967295`（=2³²−1）。
实测哨兵状态：`n=1, idx[n]=1, idx[n+1]=2`，`idx[n]-idx[n+1]` 按 uint32 无符号下溢。
根因：`truncated_bytes()` 的哨兵差值公式只对 streaming_final/CAPACITY 路径成立；
partial 批中 `idx[n]` 是 next_batch_start、`idx[n+1]` 是残留结构索引（`json_structural_indexer.h:295-297` 的哨兵
在 partial 截短后不再位于 n/n+1），错误路径直接读它们得到无意义值。**连检查 `truncated_bytes()` 的调用方也会被误导**（P3 的判据失效）。

### 2.4 错误传播差异（设计如此，但需知晓）

- DOM：stage2 立即验证，首个坏文档即 TAPE_ERROR 并终止流（`[1,]` 跨批 → TAPE_ERROR，流停止）。
- ondemand：错误在消费时才暴露。`[1,]` 跨批：消费该文档得 TAPE_ERROR，随后流在同一偏移再报一次 STREAM-ERROR 并终止（`document_stream-inl.h:361` `is_alive()` 检查保证不会继续产出文档）。`operator++` 在 `stream->error` 时置 finished（`:171`），不会无限循环。

## 3. 修复建议

1. **(P1) 分隔符快进前做廉价结构核验**：`skip_to_delimiter()` 已用二分把分隔符映射到结构索引位置；
   在跳转前用 `stream_documents_are_well_formed()`（现成的，`document_stream-inl.h:406`）核验
   [当前位置, 分隔符] 区间括号平衡且无悬挂字符串，不通过则回退 `skip_child(0)` 结构行走。
   代价每文档一次、只覆盖未读尾部。短期缓解：在 `doc/parse_many.md` 把"ndjson/json_seq 下必须消费每个文档，
   否则文档数不可信"升为显式警告，并建议过滤/计数场景用 whitespace_delimited。
2. **(P2) 根值首字节白名单**：`next_document()` 已定位下一文档首结构字符；对标量根值校验首字节
   ∈ `"-0123456789tfn"`（对象/数组已由 `[{` 保证），`,`、`]`、`xyz` 之类在流层直接报 TAPE_ERROR，
   与 DOM 行为对齐，不等消费。
3. **(P3) 严格模式选项**：给 `iterate_many/parse_many` 增加 opt-in 标志，最终批发生截断时以错误
   （如新增 TRUNCATED_DOCUMENT 或复用 TAPE_ERROR）结束流而非静默 EMPTY；默认行为不变以兼容截断下载场景。
4. **(P4) `truncated_bytes()` 加不变量保护**：`error != SUCCESS && error != CAPACITY` 时不要信哨兵差值；
   至少 `a = idx[n], b = idx[n+1]; return (a >= b && a - b <= len) ? a - b : (len - batch_start);`，
   杜绝无符号下溢产出 2³²−1 这类"看似合法"的值。
5. 文档 > batch_size 的 CAPACITY 行为正确，无需改；在文档中明确"batch_size 即单文档最大尺寸，超限整流中止"。

## 4. 可复验的安全判据（测试断言）

- **C1（截断可见性）**：流正常结束后 `truncated_bytes() == 0`；任何路径下 `truncated_bytes() <= len`
  （回归 P4：含 0x1E 的 ws 流在 TAPE_ERROR 后不得返回 2³²−1）。
- **C2（跨批等价性）**：ws 模式下，对所有合法文档 D（≤ batch_size）与所有切割点，流式逐文档
  `raw_json()` 与单发 `iterate()` 结果一致；文档数守恒。（probe4 已覆盖 string/number/container 三类。）
- **C3（无伪造文档）**：完全消费每个文档时，任何模式下产出文档数 == 预期；ndjson/json_seq 下
  未消费文档时，若文档内含分隔符，流必须以错误结束而非产出额外文档（修复 P1 后的断言）。
- **C4（错误即终止）**：任一文档出错后，`++` 迭代器立即 `at_end()`，不再产出文档（现有行为，防回归）。
- **C5（CAPACITY 语义）**：单文档 > batch_size 时流以 CAPACITY 中止且 `truncated_bytes() == len - 出错批起始`。
- **C6（垃圾不交付）**：流不交付首字节非法的根标量文档（`,`、`]`、未引用裸 token），流层即报错（修复 P2 后的断言）。
