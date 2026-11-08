# 05: `crypto-engine` 错误类型归域 + `server-core` 边界映射

**What to build:** 中性密码原语 crate 零内部 crate 依赖、自带 `CryptoError`；链路加密边界按变体语义显式映射回信封错误，对外错误文案与现状逐字一致；桌面宿主直连注册表的调用改型由 09 承接。

**Blocked by:** 03（同一链路加密文件与错误边界，避免并行改同一面）

**Status:** ready-for-agent

- [ ] `CryptoError` 覆盖五类语义（非法密钥长度 / 非法 nonce 长度 / 未知算法 / 其它非法输入 / 算法执行失败），`Display` 返回原文。
- [ ] 所有 provider trait / 注册表 / 算法实现的返回类型改为 `CryptoResult`；`crypto-engine` 依赖清单零内部 crate。
- [ ] `cargo tree --offline -e normal -i wasmnest-server-base` 从 `crypto-engine` 无输出。
- [ ] `server-core` 按变体语义映射回 `InvalidInput` / `Internal`，对外文案与现状逐字一致；链路加密测试绿。
- [ ] 既有算法向量测试保留；新增 `CryptoError` 的 Display 与映射测试。
