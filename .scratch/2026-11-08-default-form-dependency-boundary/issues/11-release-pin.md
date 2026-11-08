# 11: 发版收口：lib tag + 平台 manifest + 跨仓锁

**What to build:** P0 与穿透整合完成后，能力仓打精确 tag，平台 `release-manifest` 的 lib 指针指向该提交并通过清单校验；测试仓 wire / permission 锁确认零漂移。

**Blocked by:** 07、08、09、10

**Status:** ready-for-agent

- [ ] 能力仓提交树干净后打 `lib-vX.Y.Z` tag。
- [ ] 平台 `release-manifest` 的 lib tag 指向精确提交；契约版本 / 哈希按需同步。
- [ ] `check:manifest` 绿（HEAD == tag 且工作树干净）。
- [ ] 测试仓 `wire_drift_locks` 与 `permission_vocabulary_lock` 跑一次，确认零漂移。
- [ ] 平台适配与穿透整合完成前不打 tag（fail-visible，不指向不可编译提交）。
