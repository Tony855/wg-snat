#!/bin/bash
# ============================================================
# restore-wg-snat.sh — 恢复入口（薄壳）
# 逻辑唯一来源为 wg-snat-lib.sh，本文件不包含业务逻辑
# 由 wg-snat-restore.service（开机）调用；也可手动执行
# ============================================================
source /usr/local/bin/wg-snat-lib.sh
restore_nat_rules
