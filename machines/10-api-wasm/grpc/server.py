"""Acme inventory gRPC server - intentionally vulnerable (WSTG-APIT-10).

  * plaintext HTTP/2 (h2c), no TLS, no channel credentials
  * server reflection enabled: services/methods/protos are enumerable
  * GetItem / ListItems require an x-api-token metadata header
  * AdminDumpUsers / AdminSetStock enforce NOTHING (method-level authz gap)
"""
from concurrent import futures

import grpc
from grpc_reflection.v1alpha import reflection

import lab_pb2
import lab_pb2_grpc

VALID_TOKEN = "svc-token-alice"

ITEMS = {
    1: {"id": 1, "name": "widget", "stock": 120, "internal_note": "supplier: Shenzhen Widgets Ltd, cost 2.10"},
    2: {"id": 2, "name": "gadget", "stock": 45, "internal_note": "margin 71%, do not publish"},
    3: {"id": 3, "name": "gizmo", "stock": 8, "internal_note": "recall pending QA-2231"},
}

USERS = [
    {"id": 1, "username": "alice", "password_hash": "pbkdf2$grpc-lab-alice-hash", "api_token": "ak_alice_grpc_7c1f", "is_admin": False},
    {"id": 2, "username": "bob", "password_hash": "pbkdf2$grpc-lab-bob-hash", "api_token": "ak_bob_grpc_9d3e", "is_admin": False},
    {"id": 3, "username": "admin", "password_hash": "pbkdf2$grpc-lab-admin-hash", "api_token": "ak_admin_grpc_0a0a", "is_admin": True},
]


def _require_token(context):
    md = dict(context.invocation_metadata())
    if md.get("x-api-token") != VALID_TOKEN:
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "x-api-token metadata required")


class Inventory(lab_pb2_grpc.InventoryServicer):
    def GetItem(self, request, context):
        _require_token(context)
        item = ITEMS.get(request.id)
        if item is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "no such item")
        return lab_pb2.Item(**item)

    def ListItems(self, request, context):
        _require_token(context)
        return lab_pb2.ItemList(items=[lab_pb2.Item(**i) for i in ITEMS.values()])

    def AdminDumpUsers(self, request, context):
        # VULN: privileged RPC, no authentication or authorization whatsoever.
        return lab_pb2.UserDump(users=[lab_pb2.UserRecord(**u) for u in USERS])

    def AdminSetStock(self, request, context):
        # VULN: privileged write RPC, also unauthenticated.
        if request.id not in ITEMS:
            context.abort(grpc.StatusCode.NOT_FOUND, "no such item")
        ITEMS[request.id]["stock"] = request.stock
        return lab_pb2.Item(**ITEMS[request.id])


def main():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    lab_pb2_grpc.add_InventoryServicer_to_server(Inventory(), server)
    service_names = (
        lab_pb2.DESCRIPTOR.services_by_name["Inventory"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)
    server.add_insecure_port("[::]:50051")  # plaintext h2c, no TLS
    server.start()
    print("inventory gRPC listening on :50051 (plaintext, reflection on)")
    server.wait_for_termination()


if __name__ == "__main__":
    main()