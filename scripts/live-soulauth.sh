#!/usr/bin/env bash
# Live SoulAuth 集成套件（CONF-01 §32、R21–R23）：对着一个真正运行的 SoulAuth 完成
# AIActor 认证并读回认证事实。核心实验不依赖这条路径；它单独跑、单独出证据。
#
#   SOULAUTH_SRC=/path/to/SoulAuth bash scripts/live-soulauth.sh
#
# 需要：surreal、cargo、python3、curl。SOULAUTH_SRC 是 SoulAuth 源码检出（任意提交；
# 记录进证据的是它的 HEAD）。没有 target/debug/soulauth 时会在那里 cargo build 一次。
#
# 产物：results/live/soulauth/{ai_actor,human,negative,manifest}.json（令牌只留指纹）。
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SOULAUTH_SRC:?set SOULAUTH_SRC to a SoulAuth source checkout}"
for t in surreal cargo python3 curl; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done
SOULAUTH_SRC="$(cd "$SOULAUTH_SRC" && pwd)"
SURREAL_PORT="${SURREAL_PORT:-8310}"
APP_PORT="${APP_PORT:-8311}"
DB="http://127.0.0.1:${SURREAL_PORT}"
APP="http://127.0.0.1:${APP_PORT}"
OUT="${OUT:-results/live/soulauth}"
WORK="$(mktemp -d)"
DB_PID=""; APP_PID=""
cleanup() { [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null; [ -n "$DB_PID" ] && kill "$DB_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

wait_for() {   # $1=url $2=name
    local n=0
    while [ $n -lt 180 ]; do
        [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$1" 2>/dev/null)" != "000" ] && return 0
        sleep 0.5; n=$((n+1))
    done
    echo "$2 did not come up within 90s" >&2; return 1
}
sql() {
    curl -sS --max-time 15 -u root:root -H 'Accept: application/json' \
        -H 'surreal-ns: auth' -H 'surreal-db: main' --data-binary "$1" "${DB}/sql"
}
jfield() { python3 -c "import json,sys;d=json.load(open('$WORK/body'));print(d$1)"; }
req() {   # $1=method $2=path … → status; body in $WORK/body
    local m="$1" p="$2"; shift 2
    curl -sS --max-time 25 -o "$WORK/body" -w '%{http_code}' -X "$m" "${APP}${p}" "$@" 2>/dev/null || echo 000
}
need() { [ "$1" = "$2" ] || { echo "$3: expected HTTP $1, got $2: $(cat "$WORK/body" 2>/dev/null | head -c 300)" >&2; exit 1; }; }

SOULAUTH_COMMIT="$(git -C "$SOULAUTH_SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "soulauth: $SOULAUTH_SRC @ $SOULAUTH_COMMIT"

if [ ! -x "$SOULAUTH_SRC/target/debug/soulauth" ]; then
    echo "building soulauth"
    (cd "$SOULAUTH_SRC" && cargo build --locked -q)
fi
echo "building srg-live"
cargo build --locked -q -p srg-live

surreal start --bind "127.0.0.1:${SURREAL_PORT}" --user root --pass root memory > "$WORK/surreal.log" 2>&1 &
DB_PID=$!
wait_for "${DB}/health" SurrealDB
for f in schema.sql initial_data.sql; do
    surreal import --endpoint "$DB" --user root --pass root --namespace auth --database main \
        "$SOULAUTH_SRC/$f" > "$WORK/import.log" 2>&1 || { cat "$WORK/import.log"; exit 1; }
done

(
    cd "$SOULAUTH_SRC"
    DATABASE_URL="127.0.0.1:${SURREAL_PORT}" DATABASE_USER=root DATABASE_PASS=root \
    DATABASE_NAMESPACE=auth DATABASE_NAME=main \
    JWT_SECRET=0123456789abcdef0123456789abcdef \
    MFA_SECRET_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    AUDIT_INTEGRITY_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= \
    GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
    OAUTH_REDIRECT_URL="${APP}/api/auth/callback" \
    SMTP_HOST=127.0.0.1 SMTP_PORT=1 SMTP_FROM=noreply@example.com SMTP_INSECURE=true \
    APP_URL="$APP" EMAIL_VERIFICATION_ENABLED=false \
    BIND_ADDR="127.0.0.1:${APP_PORT}" RUST_LOG=soulauth=warn \
    exec ./target/debug/soulauth
) > "$WORK/app.log" 2>&1 &
APP_PID=$!
wait_for "${APP}/api/oidc/jwks" SoulAuth || { cat "$WORK/app.log"; exit 1; }

# 一个人类账号：先做管理员（注册 AIActor 需要 actors.write），再作为人类自省的对象。
EMAIL="live-operator@example.com"; PASSWORD="CorrectHorse42!"
need 200 "$(req POST /api/auth/register -H 'Content-Type: application/json' \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"username\":\"liveoperator\"}")" "register operator"
USER_KEY="$(sql "SELECT VALUE type::string(id) FROM user WHERE email = '${EMAIL}' LIMIT 1" | python3 -c "import json,sys;r=json.load(sys.stdin)[0]['result'];print(r[0].split(':',1)[1].strip('\`'))")"
sql "CREATE user_role CONTENT { user_id: (SELECT VALUE subject_id FROM type::record('user','${USER_KEY}'))[0], role_id: role:admin, assigned_at: 0, assigned_by: actor_identity:system }" > /dev/null
need 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")" "operator login"
ADMIN_TOK="$(jfield "['token']")"

# AIActor：种子只存在于这个进程树里，SoulAuth 只拿到公钥。
SEED_HEX="$(printf 'srg-live-agent' | sha256sum | cut -c1-64)"
PUBLIC_KEY="$(./target/debug/srg-live keygen --seed-hex "$SEED_HEX")"
need 200 "$(req POST /api/actors -H "Authorization: Bearer ${ADMIN_TOK}" -H 'Content-Type: application/json' \
    -d "{\"public_key\":\"${PUBLIC_KEY}\",\"label\":\"srg-live\"}")" "register AI actor"
ACTOR_ID="$(jfield "['actor']['id']")"
echo "ai actor registered: $ACTOR_ID"

./target/debug/srg-live run --base-url "$APP" --actor-id "$ACTOR_ID" --seed-hex "$SEED_HEX" \
    --human-email "$EMAIL" --human-password "$PASSWORD" \
    --soulauth-commit "$SOULAUTH_COMMIT" --out "$OUT"
