"""GraphQL schema for the Acme platform - intentionally vulnerable (APIT-99).

  * introspection enabled, no depth / complexity / alias limits
  * field-level authorization gaps: nested owner objects expose secrets
  * login mutation has no rate limiting (REST login does) -> alias batching
  * mutations skip object-level and function-level authorization
"""
import hashlib
import sqlite3

import graphene

DB = "/tmp/acme.db"
HOOKS = {}  # app.py injects issue_token here after import


def _hash_pw(pw):
    return "pbkdf2$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), b"acme-static-salt", 1000).hex()


def _rows(ctx, sql, args=()):
    return [dict(r) for r in ctx["db"].execute(sql, args).fetchall()]


def _row(ctx, sql, args=()):
    r = ctx["db"].execute(sql, args).fetchone()
    return dict(r) if r else None


class UserType(graphene.ObjectType):
    id = graphene.Int()
    uuid = graphene.String()
    username = graphene.String()
    email = graphene.String()
    password_hash = graphene.String()   # field-level gap: secrets in the graph
    api_token = graphene.String()
    is_admin = graphene.Boolean()
    balance = graphene.Int()
    ssn = graphene.String()
    internal_notes = graphene.String()
    orders = graphene.List(lambda: OrderType)

    def resolve_orders(user, info):
        # No authorization: any caller can walk user -> orders -> owner -> ...
        return _rows(info.context, "SELECT * FROM orders WHERE owner_id=?", (user["id"],))


class OrderType(graphene.ObjectType):
    id = graphene.Int()
    uuid = graphene.String()
    owner_id = graphene.Int()
    item = graphene.String()
    amount = graphene.Int()
    status = graphene.String()
    owner = graphene.Field(UserType)

    def resolve_owner(order, info):
        # Field-level authorization gap: full owner model, whoever asks.
        return _row(info.context, "SELECT * FROM users WHERE id=?", (order["owner_id"],))


class Query(graphene.ObjectType):
    me = graphene.Field(UserType)
    users = graphene.List(UserType)
    user = graphene.Field(UserType, id=graphene.Int(required=True))
    orders = graphene.List(OrderType)
    order = graphene.Field(OrderType, id=graphene.Int(required=True))

    def resolve_me(root, info):
        return info.context.get("user")

    def resolve_users(root, info):
        if not info.context.get("user"):
            raise Exception("authentication required")
        return _rows(info.context, "SELECT * FROM users")

    def resolve_user(root, info, id):
        return _row(info.context, "SELECT * FROM users WHERE id=?", (id,))

    def resolve_orders(root, info):
        return _rows(info.context, "SELECT * FROM orders")

    def resolve_order(root, info, id):
        return _row(info.context, "SELECT * FROM orders WHERE id=?", (id,))


class Login(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    token = graphene.String()
    user_id = graphene.Int()
    error = graphene.String()

    def mutate(root, info, username, password):
        # No rate limiting here - alias batching brute-forces freely.
        u = _row(info.context, "SELECT * FROM users WHERE username=?", (username,))
        if u is None or u["password_hash"] != _hash_pw(password):
            return Login(error="bad credentials")
        return Login(token=HOOKS["issue_token"](u["id"]), user_id=u["id"])


class UpdateOrderStatus(graphene.Mutation):
    class Arguments:
        order_id = graphene.Int(required=True)
        status = graphene.String(required=True)

    order = graphene.Field(OrderType)
    error = graphene.String()

    def mutate(root, info, order_id, status):
        if not info.context.get("user"):
            return UpdateOrderStatus(error="authentication required")
        # Mutation skips object-level authorization: any user, any order.
        o = _row(info.context, "SELECT * FROM orders WHERE id=?", (order_id,))
        if not o:
            return UpdateOrderStatus(error="no such order")
        info.context["db"].execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        info.context["db"].commit()
        return UpdateOrderStatus(order=_row(info.context, "SELECT * FROM orders WHERE id=?", (order_id,)))


class SetUserRole(graphene.Mutation):
    class Arguments:
        user_id = graphene.Int(required=True)
        is_admin = graphene.Boolean(required=True)

    user = graphene.Field(UserType)
    error = graphene.String()

    def mutate(root, info, user_id, is_admin):
        if not info.context.get("user"):
            return SetUserRole(error="authentication required")
        # Mutation skips function-level authorization: no admin check at all.
        info.context["db"].execute("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))
        info.context["db"].commit()
        return SetUserRole(user=_row(info.context, "SELECT * FROM users WHERE id=?", (user_id,)))


class Mutations(graphene.ObjectType):
    login = Login.Field()
    update_order_status = UpdateOrderStatus.Field()
    set_user_role = SetUserRole.Field()


schema = graphene.Schema(query=Query, mutation=Mutations, auto_camelcase=True)


def execute(payload, context):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    ctx = dict(context)
    ctx["db"] = con
    try:
        result = schema.execute(
            payload.get("query"),
            variables=payload.get("variables"),
            operation_name=payload.get("operationName"),
            context=ctx,
        )
        out = {}
        if result.data is not None:
            out["data"] = result.data
        if result.errors:
            out["errors"] = [{"message": e.message} for e in result.errors]
        return out
    finally:
        con.close()