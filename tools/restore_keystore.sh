#!/usr/bin/env bash
# 在 CI 里恢复签名材料。
#
# 优先从 Actions Secrets 读取（转公开后的唯一正确来源）：
#   LHASA_KEYSTORE_B64    keystore 文件内容的单行 base64
#   LHASA_STORE_PASSWORD  storePassword
#   LHASA_KEY_PASSWORD    keyPassword（可省略）
#   LHASA_KEY_ALIAS       keyAlias（默认 lhasa26）
#
# 未配置时回退到历史提交里的 keystore —— 仅用于迁移期；转公开后
# 应当删除该回退分支（历史里的旧 blob 不应再被 CI 当作来源）。
set -euo pipefail

mkdir -p keystore

if [ -n "${LHASA_KEYSTORE_B64:-}" ]; then
  printf '%s' "$LHASA_KEYSTORE_B64" | base64 -d > keystore/lhasa26.jks
  : "${LHASA_STORE_PASSWORD:?缺少 LHASA_STORE_PASSWORD}"
  {
    echo "storeFile=keystore/lhasa26.jks"
    echo "storePassword=${LHASA_STORE_PASSWORD}"
    echo "keyAlias=${LHASA_KEY_ALIAS:-lhasa26}"
    echo "keyPassword=${LHASA_KEY_PASSWORD:-$LHASA_STORE_PASSWORD}"
  } > keystore/keystore.properties
  chmod 600 keystore/keystore.properties keystore/lhasa26.jks
  echo "签名材料来自 Secrets（${#LHASA_KEYSTORE_B64} 字符 base64）"
else
  echo "::warning::未配置 LHASA_KEYSTORE_B64，回退到历史提交里的 keystore（迁移期路径）"
  git show 535ee09ab2aa2c9bd8cc6e76b2159f6c4e1cef4e:keystore/lhasa26.jks > keystore/lhasa26.jks
  cat > keystore/keystore.properties <<'EOF'
storeFile=keystore/lhasa26.jks
storePassword=lhasa26pass
keyAlias=lhasa26
keyPassword=lhasa26pass
EOF
fi

ls -l keystore/lhasa26.jks keystore/keystore.properties
