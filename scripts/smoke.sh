#!/bin/sh
# End-to-end smoke test.
#
# Builds the "test" image (fixture users are created inside the image —
# host accounts are never read), boots idaas against them, and walks the
# whole authorization-code flow with curl, including the admin API and a
# managed (API-created) user. Only touches the docker daemon and this
# repo's build context.
set -eu

IMAGE="${IMAGE:-idaas:test}"
NAME="${NAME:-idaas-smoke}"
# CI sets SMOKE_SKIP_BUILD=1 when the test image was built by a previous step
PORT="${PORT:-18080}"
B="http://127.0.0.1:$PORT"
REDIR="http://127.0.0.1:$PORT/callback"
# RFC 7636 appendix B PKCE pair
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
ADMIN_HDR="Authorization: Bearer smoke-admin-token"

step() { printf 'smoke: %s\n' "$*"; }
fail() {
    printf 'smoke: FAIL: %s\n' "$*" >&2
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    exit 1
}

# login_get_code <jar> <user> <pass> -> prints the redirect Location on
# success; prints nothing and returns non-zero when login is rejected.
login_get_code() {
    _jar=$1; _u=$2; _p=$3
    _pg=$(curl -sf -c "$_jar" --get \
        --data-urlencode "response_type=code" \
        --data-urlencode "client_id=smoke-app" \
        --data-urlencode "redirect_uri=$REDIR" \
        --data-urlencode "scope=openid profile email groups" \
        --data-urlencode "state=st-$_u" \
        --data-urlencode "nonce=n-$_u" \
        --data-urlencode "code_challenge=$CHALLENGE" \
        --data-urlencode "code_challenge_method=S256" \
        "$B/authorize") || return 1
    _csrf=$(printf '%s' "$_pg" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
    [ -n "$_csrf" ] || return 1
    _loc=$(curl -sf -b "$_jar" -c "$_jar" -o /dev/null -D - -X POST \
        --data "username=$_u&password=$_p&csrf=$_csrf" "$B/login" \
        | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | head -1) || return 1
    [ -n "$_loc" ] || return 1
    printf '%s\n' "$_loc"
}

if [ "${SMOKE_SKIP_BUILD:-0}" != "1" ]; then
    step "building test image"
    docker build --target test -t "$IMAGE" . || fail "image build"
else
    step "using prebuilt test image $IMAGE"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
step "starting container"
docker run -d --name "$NAME" \
    -p "127.0.0.1:$PORT:8080" \
    -e IDAAS_ISSUER="$B" \
    -e IDAAS_EMAIL_DOMAIN=example.com \
    -e IDAAS_CLIENTS_FILE=/src/tests/clients.smoke.conf \
    -e IDAAS_ADMIN_NETWORKS="127.0.0.0/8,172.16.0.0/12" \
    -e IDAAS_ADMIN_TOKEN=smoke-admin-token \
    --cap-drop ALL --security-opt no-new-privileges \
    "$IMAGE" /src/build/idaas >/dev/null || fail "container start"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

i=0
until curl -sf "$B/healthz" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "server did not come up"
    sleep 0.2
done

J=$(mktemp)

step "discovery document"
curl -sf "$B/.well-known/openid-configuration" | grep -q "\"issuer\":\"$B\"" || fail "discovery issuer"
step "jwks document"
curl -sf "$B/jwks.json" | grep -q '"kty":"RSA"' || fail "jwks"

step "authorize -> login page"
PAGE=$(curl -sf -c "$J" --get \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "scope=openid profile email groups" \
    --data-urlencode "state=xyz123" \
    --data-urlencode "nonce=n-abc" \
    --data-urlencode "code_challenge=$CHALLENGE" \
    --data-urlencode "code_challenge_method=S256" \
    "$B/authorize") || fail "authorize request"
echo "$PAGE" | grep -q 'name="csrf"' || fail "login form"
CSRF=$(printf '%s' "$PAGE" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$CSRF" ] || fail "csrf extraction"

step "wrong password rejected"
OUT=$(curl -sf -b "$J" -c "$J" -X POST \
    --data "username=alice&password=WRONG&csrf=$CSRF" "$B/login") || fail "login request"
echo "$OUT" | grep -q 'Invalid username or password' || fail "expected generic error"

step "system account (uid gate) rejected"
OUT=$(curl -sf -b "$J" -c "$J" -X POST \
    --data "username=svcdaemon&password=svc-pass-3&csrf=$CSRF" "$B/login") || fail "login request"
echo "$OUT" | grep -q 'Invalid username or password' || fail "expected uid-gate rejection"

step "correct login -> code redirect"
LOC=$(curl -sf -b "$J" -c "$J" -o /dev/null -D - -X POST \
    --data "username=alice&password=alice-pass-1&csrf=$CSRF" "$B/login" \
    | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | head -1) || fail "login request"
case "$LOC" in
    "$REDIR"?code=*) ;;
    *) fail "no code redirect (got: $LOC)" ;;
esac
echo "$LOC" | grep -q 'state=xyz123' || fail "state missing"
CODE=${LOC#*code=}
CODE=${CODE%%&*}

step "token exchange (PKCE)"
RESP=$(curl -sf -X POST \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "code=$CODE" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "code_verifier=$VERIFIER" \
    "$B/token") || fail "token request"
echo "$RESP" | grep -q '"access_token"' || fail "no access token"
echo "$RESP" | grep -q '"id_token"' || fail "no id token"
AT=$(printf '%s' "$RESP" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
RT=$(printf '%s' "$RESP" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
[ -n "$AT" ] && [ -n "$RT" ] || fail "token extraction"

step "userinfo"
UI=$(curl -sf -H "Authorization: Bearer $AT" "$B/userinfo") || fail "userinfo request"
echo "$UI" | grep -q '"sub":"alice"' || fail "userinfo sub"
echo "$UI" | grep -q '"preferred_username":"alice"' || fail "userinfo profile claim"
echo "$UI" | grep -q '"email":"alice@example.com"' || fail "userinfo email"
echo "$UI" | grep -q '"groups"' || fail "userinfo groups"

step "refresh grant"
RESP2=$(curl -sf -X POST \
    --data "grant_type=refresh_token&client_id=smoke-app&refresh_token=$RT" "$B/token") || fail "refresh request"
AT2=$(printf '%s' "$RESP2" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$AT2" ] && [ "$AT2" != "$AT" ] || fail "refresh did not rotate"
UI2=$(curl -sf -H "Authorization: Bearer $AT2" "$B/userinfo") || fail "userinfo after refresh"
echo "$UI2" | grep -q '"sub":"alice"' || fail "userinfo sub after refresh"

step "replayed authorization code rejected"
CODE3=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "code=$CODE" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "code_verifier=$VERIFIER" \
    "$B/token")
[ "$CODE3" = "400" ] || fail "code replay not rejected ($CODE3)"

step "bad client secret rejected"
CODE4=$(curl -s -o /dev/null -w '%{http_code}' -u smoke-conf:WRONG -X POST \
    --data "grant_type=authorization_code&code=x" \
    --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/cb2" \
    "$B/token")
[ "$CODE4" = "401" ] || fail "bad secret accepted ($CODE4)"

# ---- account chooser (the jar $J still remembers alice) ----

step "re-authorize with a signed-in account shows the chooser"
CHOOSER=$(curl -sf -b "$J" -c "$J" --get \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "scope=openid profile email groups" \
    --data-urlencode "state=choose1" \
    --data-urlencode "nonce=n-choose1" \
    --data-urlencode "code_challenge=$CHALLENGE" \
    --data-urlencode "code_challenge_method=S256" \
    "$B/authorize") || fail "authorize request"
echo "$CHOOSER" | grep -q 'action="/choose"' || fail "chooser page"
echo "$CHOOSER" | grep -q 'name="acct" value="alice"' || fail "alice not listed"
echo "$CHOOSER" | grep -q 'Use another account' || fail "other-account link"
CCSRF=$(printf '%s' "$CHOOSER" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$CCSRF" ] || fail "chooser csrf extraction"

step "confirming the signed-in account mints a code"
LOC=$(curl -sf -b "$J" -c "$J" -o /dev/null -D - -X POST \
    --data "acct=alice&csrf=$CCSRF" "$B/choose" \
    | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | head -1) || fail "choose request"
case "$LOC" in
    "$REDIR"?code=*) ;;
    *) fail "no code redirect after choose (got: $LOC)" ;;
esac
echo "$LOC" | grep -q 'state=choose1' || fail "state missing after choose"

step "choose with a bad csrf is rejected"
S=$(curl -s -o /dev/null -w '%{http_code}' -b "$J" -X POST \
    --data "acct=alice&csrf=WRONG" "$B/choose")
[ "$S" = "403" ] || fail "choose with bad csrf accepted ($S)"

step "second account via 'use another account' gets a code"
CHOOSER2=$(curl -sf -b "$J" -c "$J" --get \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "scope=openid profile email groups" \
    --data-urlencode "state=choose2" \
    --data-urlencode "nonce=n-choose2" \
    --data-urlencode "code_challenge=$CHALLENGE" \
    --data-urlencode "code_challenge_method=S256" \
    "$B/authorize") || fail "authorize request"
echo "$CHOOSER2" | grep -q 'name="acct" value="alice"' || fail "alice not listed"
LOGIN2=$(curl -sf -b "$J" -c "$J" "$B/login") || fail "login page"
LCSRF=$(printf '%s' "$LOGIN2" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$LCSRF" ] || fail "login csrf extraction"
LOCB=$(curl -sf -b "$J" -c "$J" -o /dev/null -D - -X POST \
    --data "username=bob&password=bob-pass-2&csrf=$LCSRF" "$B/login" \
    | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | head -1) || fail "bob login"
case "$LOCB" in
    "$REDIR"?code=*) ;;
    *) fail "bob: no code redirect (got: $LOCB)" ;;
esac
echo "$LOCB" | grep -q 'state=choose2' || fail "bob: state missing"

step "chooser lists both remembered accounts"
CHOOSER3=$(curl -sf -b "$J" -c "$J" --get \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "scope=openid profile email groups" \
    --data-urlencode "state=choose3" \
    --data-urlencode "nonce=n-choose3" \
    --data-urlencode "code_challenge=$CHALLENGE" \
    --data-urlencode "code_challenge_method=S256" \
    "$B/authorize") || fail "authorize request"
echo "$CHOOSER3" | grep -q 'name="acct" value="bob"' || fail "bob not listed"
echo "$CHOOSER3" | grep -q 'name="acct" value="alice"' || fail "alice not listed"
CCSRF3=$(printf '%s' "$CHOOSER3" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$CCSRF3" ] || fail "chooser csrf extraction"

step "choosing an unremembered account is refused"
OUT=$(curl -sf -b "$J" -X POST --data "acct=eve&csrf=$CCSRF3" "$B/choose") \
    || fail "choose request"
echo "$OUT" | grep -q 'no longer signed in' || fail "unknown account accepted"

step "choosing the non-active account issues a code for it"
LOCA=$(curl -sf -b "$J" -c "$J" -o /dev/null -D - -X POST \
    --data "acct=alice&csrf=$CCSRF3" "$B/choose" \
    | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | head -1) || fail "choose request"
case "$LOCA" in
    "$REDIR"?code=*) ;;
    *) fail "no code redirect for chosen account (got: $LOCA)" ;;
esac
echo "$LOCA" | grep -q 'state=choose3' || fail "state missing for chosen account"
CA=${LOCA#*code=}
CA=${CA%%&*}
RESPA=$(curl -sf -X POST \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "code=$CA" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "code_verifier=$VERIFIER" \
    "$B/token") || fail "token exchange for chosen account"
ATA=$(printf '%s' "$RESPA" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$ATA" ] || fail "access token for chosen account"
UIA=$(curl -sf -H "Authorization: Bearer $ATA" "$B/userinfo") || fail "userinfo for chosen account"
echo "$UIA" | grep -q '"sub":"alice"' || fail "chosen account did not get the code"

# ---- admin API (mynetworks gate + token) and managed users ----

step "admin api: refused without token"
S=$(curl -s -o /dev/null -w '%{http_code}' "$B/api/users")
[ "$S" = "401" ] || fail "admin without token ($S)"

step "admin api: create managed user"
curl -sf -H "$ADMIN_HDR" -X POST \
    --data-urlencode "username=dan" \
    --data-urlencode "password=dan-pass-99" \
    --data-urlencode "name=Dan M" \
    --data-urlencode "email=dan@corp.example" \
    --data-urlencode "groups=dev,ops" \
    "$B/api/users" | grep -q '"username":"dan"' || fail "managed user create"

step "admin api: duplicate rejected"
S=$(curl -s -o /dev/null -w '%{http_code}' -H "$ADMIN_HDR" -X POST \
    --data-urlencode "username=dan" \
    --data-urlencode "password=dan-pass-99" \
    "$B/api/users")
[ "$S" = "409" ] || fail "duplicate create accepted ($S)"

step "managed user can sign in and gets claims"
J2=$(mktemp)
LOC2=$(login_get_code "$J2" dan dan-pass-99) || fail "managed user login"
case "$LOC2" in
    "$REDIR"?code=*) ;;
    *) fail "managed user: no code redirect (got: $LOC2)" ;;
esac
C2=${LOC2#*code=}
C2=${C2%%&*}
RESP5=$(curl -sf -X POST \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "client_id=smoke-app" \
    --data-urlencode "code=$C2" \
    --data-urlencode "redirect_uri=$REDIR" \
    --data-urlencode "code_verifier=$VERIFIER" \
    "$B/token") || fail "managed user token exchange"
AT5=$(printf '%s' "$RESP5" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$AT5" ] || fail "managed user access token"
UI5=$(curl -sf -H "Authorization: Bearer $AT5" "$B/userinfo") || fail "managed userinfo"
echo "$UI5" | grep -q '"sub":"dan"' || fail "managed sub"
echo "$UI5" | grep -q '"name":"Dan M"' || fail "managed name claim"
echo "$UI5" | grep -q '"email":"dan@corp.example"' || fail "managed email claim"
echo "$UI5" | grep -q '"dev"' || fail "managed groups claim"

step "admin api: password update rotates credentials"
curl -sf -H "$ADMIN_HDR" -X PUT \
    --data-urlencode "password=new-pass-77" "$B/api/users/dan" >/dev/null || fail "password update"
J3=$(mktemp)
LOC3=$(login_get_code "$J3" dan new-pass-77) || fail "login with new password"
[ -n "$LOC3" ] || fail "no redirect with new password"
if LOCX=$(login_get_code "$(mktemp)" dan dan-pass-99); then
    fail "old password still works"
fi

step "admin api: disable blocks login"
curl -sf -H "$ADMIN_HDR" -X PUT --data "disabled=1" "$B/api/users/dan" >/dev/null || fail "disable"
if LOCY=$(login_get_code "$(mktemp)" dan new-pass-77); then
    fail "disabled user logged in"
fi

step "admin api: delete, then 404"
curl -sf -H "$ADMIN_HDR" -X DELETE "$B/api/users/dan" >/dev/null || fail "delete"
S=$(curl -s -o /dev/null -w '%{http_code}' -H "$ADMIN_HDR" "$B/api/users/dan")
[ "$S" = "404" ] || fail "deleted user still there ($S)"
if LOCZ=$(login_get_code "$(mktemp)" dan new-pass-77); then
    fail "deleted user logged in"
fi

rm -f "$J" "$J2" "$J3"
docker rm -f "$NAME" >/dev/null
trap - EXIT
step "ALL PASSED"
