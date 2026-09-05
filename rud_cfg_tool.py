#!/usr/bin/env python3

import argparse
import base64
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as nacl_random


FORMAT_VERSION = 1
DEFAULT_KEY_ID = "android-v1"


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def compact_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str, value: dict) -> None:
    Path(path).write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def validate_bootstrap(payload: dict) -> None:
    expected = {
        "version",
        "revision",
        "issued_at",
        "expires_at",
        "provisioning_api_server",
    }
    if set(payload) != expected:
        raise ValueError("bootstrap 字段不完整或包含未知字段")
    if payload["version"] != FORMAT_VERSION:
        raise ValueError(f"version 必须是 {FORMAT_VERSION}")
    if not isinstance(payload["revision"], int) or payload["revision"] <= 0:
        raise ValueError("revision 必须是正整数")
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise ValueError("issued_at 和 expires_at 必须是 Unix 秒整数")
    if payload["expires_at"] <= payload["issued_at"]:
        raise ValueError("expires_at 必须晚于 issued_at")
    parsed = urlparse(payload["provisioning_api_server"])
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provisioning_api_server 必须是无认证、查询和 Fragment 的 HTTP/HTTPS URL")


def load_keys(path: str) -> dict:
    keys = read_json(path)
    signing_key = SigningKey(b64d(keys["sign_seed_b64"]))
    verify_key = VerifyKey(b64d(keys["sign_public_key_b64"]))
    secretbox_key = b64d(keys["secretbox_key_b64"])
    enrollment_key = b64d(keys["device_enrollment_key_b64"])
    if bytes(signing_key.verify_key) != bytes(verify_key):
        raise ValueError("签名私钥和公钥不匹配")
    if len(secretbox_key) != SecretBox.KEY_SIZE or len(enrollment_key) != 32:
        raise ValueError("SecretBox 和设备初始注册密钥必须分别为 32 字节")
    return {
        "key_id": keys.get("key_id", DEFAULT_KEY_ID),
        "signing_key": signing_key,
        "verify_key": verify_key,
        "secretbox_key": secretbox_key,
        "enrollment_key": enrollment_key,
    }


def signature_message(
    version: int, purpose: str, key_id: str, nonce: bytes, ciphertext: bytes
) -> bytes:
    return (
        b"RUD1"
        + version.to_bytes(4, "big")
        + purpose.encode("utf-8")
        + b"\0"
        + key_id.encode("utf-8")
        + b"\0"
        + nonce
        + ciphertext
    )


def gen_keys(output: str, key_id: str) -> None:
    signing_key = SigningKey.generate()
    write_json(
        output,
        {
            "version": FORMAT_VERSION,
            "key_id": key_id,
            "sign_seed_b64": b64e(bytes(signing_key)),
            "sign_public_key_b64": b64e(bytes(signing_key.verify_key)),
            "secretbox_key_b64": b64e(nacl_random(SecretBox.KEY_SIZE)),
            "device_enrollment_key_b64": b64e(nacl_random(32)),
        },
    )
    print(f"OK: wrote {output}")


def pack_bootstrap(payload_path: str, keys_path: str, output: str) -> None:
    payload = read_json(payload_path)
    validate_bootstrap(payload)
    keys = load_keys(keys_path)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    ciphertext = SecretBox(keys["secretbox_key"]).encrypt(compact_json(payload), nonce).ciphertext
    message = signature_message(
        FORMAT_VERSION, "bootstrap", keys["key_id"], nonce, ciphertext
    )
    write_json(
        output,
        {
            "version": FORMAT_VERSION,
            "purpose": "bootstrap",
            "key_id": keys["key_id"],
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "signature": b64e(keys["signing_key"].sign(message).signature),
        },
    )
    print(f"OK: wrote {output}")


def unpack_bootstrap(input_path: str, keys_path: str, output: str) -> None:
    envelope = read_json(input_path)
    expected = {"version", "purpose", "key_id", "nonce", "ciphertext", "signature"}
    if set(envelope) != expected:
        raise ValueError("rud.cfg 字段不完整或包含未知字段")
    keys = load_keys(keys_path)
    if (
        envelope["version"] != FORMAT_VERSION
        or envelope["purpose"] != "bootstrap"
        or envelope["key_id"] != keys["key_id"]
    ):
        raise ValueError("rud.cfg 版本、用途或 key_id 不匹配")
    nonce = b64d(envelope["nonce"])
    ciphertext = b64d(envelope["ciphertext"])
    signature = b64d(envelope["signature"])
    message = signature_message(
        envelope["version"], envelope["purpose"], envelope["key_id"], nonce, ciphertext
    )
    keys["verify_key"].verify(message, signature)
    payload = json.loads(SecretBox(keys["secretbox_key"]).decrypt(ciphertext, nonce))
    validate_bootstrap(payload)
    write_json(output, payload)
    print(f"OK: wrote {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Android rud.cfg 制作与验证工具")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("genkeys")
    generate.add_argument("-o", "--out", default="rud-keys.json")
    generate.add_argument("--key-id", default=DEFAULT_KEY_ID)

    pack = subparsers.add_parser("pack-bootstrap")
    pack.add_argument("-p", "--payload", required=True)
    pack.add_argument("-k", "--keys", required=True)
    pack.add_argument("-o", "--out", default="rud.cfg")

    unpack = subparsers.add_parser("unpack-bootstrap")
    unpack.add_argument("-i", "--input", required=True)
    unpack.add_argument("-k", "--keys", required=True)
    unpack.add_argument("-o", "--out", default="rud-bootstrap.json")

    args = parser.parse_args()
    try:
        if args.command == "genkeys":
            gen_keys(args.out, args.key_id)
        elif args.command == "pack-bootstrap":
            pack_bootstrap(args.payload, args.keys, args.out)
        else:
            unpack_bootstrap(args.input, args.keys, args.out)
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
