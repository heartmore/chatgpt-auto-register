"""Flask server - multi-user ChatGPT registration platform"""

import json, os, queue, time
from pathlib import Path

from flask import Flask, request, jsonify, Response, g, send_file
from flask_cors import CORS

import config, db, auth, runner

app = Flask(__name__, static_folder="public", static_url_path="")
CORS(app)

# ── Init on startup ──
db.init_db()


# ── Public routes ──
@app.route("/")
def index():
    return send_file("public/index.html")


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    d = request.json or {}
    user = db.verify_login(d.get("username", ""), d.get("password", ""))
    if not user:
        return jsonify({"ok": False, "error": "Invalid credentials"})
    token = auth.make_token(user["id"], user["username"], user["role"])
    return jsonify({"ok": True, "token": token, "role": user["role"],
                     "username": user["username"], "quota": user["quota"]})


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    d = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "").strip()
    invite_key = d.get("invite_key", "").strip().upper()

    if len(username) < 3 or len(password) < 6:
        return jsonify({"ok": False, "error": "Username >= 3 chars, password >= 6 chars"})
    if not invite_key:
        return jsonify({"ok": False, "error": "Invite key required"})

    user = db.create_user(username, password, invite_key)
    if user is None:
        return jsonify({"ok": False, "error": "Username taken or invalid invite key"})
    token = auth.make_token(user["id"], user["username"], user["role"])
    return jsonify({"ok": True, "token": token, "role": user["role"],
                     "username": user["username"], "quota": user["quota"]})


# ── Member routes ──
@app.route("/api/member/me", methods=["GET"])
@auth.login_required
def api_me():
    user = db.get_user(user_id=g.user_id)
    cfg = db.get_user_config(g.user_id)
    icloud = db.check_icloud_access(g.user_id)
    return jsonify({"ok": True, "user": user, "config": cfg,
                     "icloud": {"active": bool(icloud),
                                "remaining": icloud.get("remaining_uses", 0) if icloud else 0}})


@app.route("/api/member/config", methods=["PUT"])
@auth.login_required
def api_config():
    d = request.json or {}
    db.update_user_config(g.user_id, d)
    return jsonify({"ok": True})


@app.route("/api/member/redeem", methods=["POST"])
@auth.login_required
def api_redeem():
    d = request.json or {}
    key = d.get("key", "").strip().upper()

    # Try card first (iCloud), then invite
    card = db.redeem_card(g.user_id, key)
    if card:
        return jsonify({"ok": True, "type": "card", "product": card["product"],
                         "remaining": card["remaining"]})

    # Try invite key
    pool = db.get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM invite_keys WHERE key = %s AND is_active = TRUE AND used_count < max_uses",
                (key,),
            )
            invite = cur.fetchone()
            if invite:
                quota = invite[4]  # grant_quota index
                cur.execute("UPDATE invite_keys SET used_count = used_count + 1 WHERE key = %s", (key,))
                cur.execute("UPDATE users SET quota = quota + %s WHERE id = %s", (quota, g.user_id))
                conn.commit()
                return jsonify({"ok": True, "type": "invite", "quota_added": quota})
    except Exception:
        pass
    finally:
        pool.putconn(conn)
    return jsonify({"ok": False, "error": "Invalid key"})


@app.route("/api/member/register/start", methods=["POST"])
@auth.login_required
def api_reg_start():
    count = int((request.json or {}).get("count", 1))
    err = runner.start(g.user_id, count)
    if err != "ok":
        return jsonify({"ok": False, "error": err})
    return jsonify({"ok": True})


@app.route("/api/member/register/stop", methods=["POST"])
@auth.login_required
def api_reg_stop():
    runner.stop(g.user_id)
    return jsonify({"ok": True})


@app.route("/api/member/register/log")
@auth.login_required
def api_reg_log():
    q = runner.get_sse_queue(g.user_id)

    def stream():
        while True:
            try:
                item = q.get(timeout=25)
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({})}\n\n"

    r = Response(stream(), mimetype="text/event-stream")
    r.headers["X-Accel-Buffering"] = "no"
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.route("/api/member/history", methods=["GET"])
@auth.login_required
def api_history():
    return jsonify({"ok": True, "history": db.get_user_history(g.user_id)})


# ── Admin routes ──
@app.route("/api/admin/stats", methods=["GET"])
@auth.admin_required
def api_stats():
    return jsonify({"ok": True, **db.admin_stats()})


@app.route("/api/admin/invite-gen", methods=["POST"])
@auth.admin_required
def api_invite_gen():
    count = int((request.json or {}).get("count", config.DAILY_INVITE_COUNT))
    # Check today limit
    keys = db.gen_invite_keys(count)
    return jsonify({"ok": True, "keys": keys})


@app.route("/api/admin/invite-list", methods=["GET"])
@auth.admin_required
def api_invite_list():
    return jsonify({"ok": True, "invites": db.list_invite_keys()})


@app.route("/api/admin/invite/<int:key_id>", methods=["DELETE"])
@auth.admin_required
def api_invite_revoke(key_id):
    db.revoke_invite(key_id)
    return jsonify({"ok": True})


@app.route("/api/admin/card-gen", methods=["POST"])
@auth.admin_required
def api_card_gen():
    d = request.json or {}
    keys = db.gen_card_keys(
        count=d.get("count", 1),
        product=d.get("product", "icloud_10"),
        grant_count=d.get("grant_count", 10),
        duration_days=d.get("duration_days", 30),
    )
    return jsonify({"ok": True, "keys": keys})


@app.route("/api/admin/card-list", methods=["GET"])
@auth.admin_required
def api_card_list():
    return jsonify({"ok": True, "cards": db.list_card_keys()})


@app.route("/api/admin/card/<int:key_id>", methods=["DELETE"])
@auth.admin_required
def api_card_revoke(key_id):
    db.revoke_card(key_id)
    return jsonify({"ok": True})


@app.route("/api/admin/users", methods=["GET"])
@auth.admin_required
def api_users():
    return jsonify({"ok": True, "users": db.admin_users()})


@app.route("/api/admin/logs", methods=["GET"])
@auth.admin_required
def api_logs():
    return jsonify({"ok": True, "logs": db.admin_logs()})


@app.route("/api/admin/assets", methods=["PUT"])
@auth.admin_required
def api_assets():
    d = request.json or {}
    for k in ["icloud_cookies", "mailmanage_key"]:
        if k in d and d[k]:
            db.set_admin_asset(k, d[k])
    return jsonify({"ok": True})


@app.route("/api/admin/assets", methods=["GET"])
@auth.admin_required
def api_assets_get():
    return jsonify({"ok": True, "icloud_cookies": bool(db.get_admin_asset("icloud_cookies")),
                     "mailmanage_key": bool(db.get_admin_asset("mailmanage_key"))})


# ── Start ──
def start_server(host="0.0.0.0", port=8080):
    print(f"\nServer: http://127.0.0.1:{port}")
    print(f"Admin: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD}")
    from scheduler import start_scheduler
    start_scheduler()
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    start_server()
