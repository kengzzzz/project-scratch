#!/usr/bin/env python3
"""OpenPGP backups for Vaultwarden; restore decrypts into a new directory."""

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

DATA = Path("/bitwarden/data")
PUBLIC_KEYS = Path("/config/backup")
STATE = Path("/backup-state")
ARCHIVE_PATTERN = re.compile(r"backup\.\d{8}T\d{6}Z\.tar\.gz\.gpg")
TABLES = ("users", "ciphers", "folders", "attachments", "sends", "organizations", "collections")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def database_counts(path):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as database:
        if database.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise RuntimeError("SQLite database integrity check failed")
        tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"users", "ciphers"} <= tables:
            raise RuntimeError("Missing Vaultwarden database tables")
        return {name: database.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in TABLES if name in tables}


def snapshot(directory):
    for name in ("db.sqlite3", "rsa_key.pem"):
        if not (DATA / name).is_file() or (DATA / name).is_symlink():
            raise RuntimeError(f"Missing or unsupported required file: {name}")
    directory.mkdir(mode=0o700)
    # SQLite's online backup API includes committed WAL data from the live vault.
    with closing(sqlite3.connect(f"{(DATA / 'db.sqlite3').as_uri()}?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(directory / "db.sqlite3")) as target:
            source.backup(target)
    paths = list(DATA.glob("rsa_key*"))
    if (DATA / "config.json").exists():
        paths.append(DATA / "config.json")
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Unsupported configuration or RSA key file")
        shutil.copy2(path, directory / path.name)
    for name in ("attachments", "sends"):
        path = DATA / name
        if path.exists():
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError("Unsupported attachment or sends directory")
            shutil.copytree(path, directory / name, symlinks=True)


def manifest(directory, created):
    counts = database_counts(directory / "db.sqlite3")
    files = {}
    directories = []
    for path in sorted(directory.rglob("*")):
        name = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise RuntimeError("Snapshot contains a symlink")
        if path.is_file():
            files[name] = {"sha256": digest(path), "size": path.stat().st_size}
        elif path.is_dir():
            directories.append(name)
        else:
            raise RuntimeError("Snapshot contains an unsupported file type")
    record = {"format": 1, "created_utc": created, "files": files, "directories": directories, "database_counts": counts}
    (directory / "manifest.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    return record


def settings():
    keys = ("BACKUP_KEEP_DAYS", "RCLONE_REMOTE_NAME", "RCLONE_REMOTE_DIR")
    values = {key: os.environ.get(key, "") for key in keys}
    if any(not value for value in values.values()):
        raise RuntimeError("BACKUP_KEEP_DAYS, RCLONE_REMOTE_NAME and RCLONE_REMOTE_DIR must be set")
    if not values["BACKUP_KEEP_DAYS"].isdigit() or int(values["BACKUP_KEEP_DAYS"]) < 1:
        raise RuntimeError("BACKUP_KEEP_DAYS must be a positive number")
    return values


def rclone(*arguments):
    return ["rclone", "--config", "/config/rclone/rclone.conf", *arguments]


def remote_directory(config):
    return f"{config['RCLONE_REMOTE_NAME']}:{config['RCLONE_REMOTE_DIR'].rstrip('/')}"


def backup(config, workdir):
    fingerprints = [line.strip() for line in (PUBLIC_KEYS / "recipients.txt").read_text().splitlines() if line.strip()]
    if len(fingerprints) != 2 or len(set(fingerprints)) != 2 or any(not re.fullmatch(r"[0-9A-F]{40}", value) for value in fingerprints):
        raise RuntimeError("Expected two distinct full encryption fingerprints")
    home = workdir / "gnupg"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--no-options", "--no-autostart", "--homedir", str(home), "--batch"]
    subprocess.run(gpg + ["--import", str(PUBLIC_KEYS / "recipients.asc")], check=True, stdout=subprocess.DEVNULL)
    listing = subprocess.check_output(gpg + ["--with-colons", "--list-secret-keys"], text=True)
    if any(line.startswith(("sec:", "ssb:")) for line in listing.splitlines()):
        raise RuntimeError("Unexpected private key in backup keyring")
    recipients = [item for fingerprint in fingerprints for item in ("--recipient", fingerprint + "!")]
    subprocess.run(gpg + ["--trust-model", "always", *recipients, "--output", str(workdir / "recipient-check.gpg"), "--encrypt"], input=b"recipient check", check=True)
    created = dt.datetime.now(dt.timezone.utc)
    name = f"backup.{created.strftime('%Y%m%dT%H%M%SZ')}.tar.gz.gpg"
    archive = workdir / name
    directory = workdir / "snapshot"
    snapshot(directory)
    record = manifest(directory, created.isoformat())
    tar = subprocess.Popen(["tar", "--create", "--gzip", "--file", "-", "--directory", str(directory), "--", "."], stdout=subprocess.PIPE)
    try:
        encryption = subprocess.run(gpg + ["--trust-model", "always", "--cipher-algo", "AES256", "--compress-algo", "none", *recipients, "--output", str(archive), "--encrypt"], stdin=tar.stdout)
    finally:
        tar.stdout.close()
        tar_status = tar.wait()
    if encryption.returncode or tar_status:
        raise RuntimeError("Archive creation or encryption failed; nothing uploaded")
    receipt = {"archive": name, "sha256": digest(archive), "size": archive.stat().st_size, "created_utc": created.isoformat(), "recipients": fingerprints, "manifest_sha256": digest(directory / "manifest.json"), "database_counts": record["database_counts"], "file_count": len(record["files"])}
    target = remote_directory(config)
    subprocess.run(rclone("copyto", str(archive), f"{target}/{name}", "--immutable"), check=True)
    subprocess.run(rclone("delete", target, "--min-age", config["BACKUP_KEEP_DAYS"] + "d", "--include", "backup.*.tar.gz.gpg", "--include", "backup.*.7z"), check=True)
    STATE.mkdir(mode=0o700, exist_ok=True)
    pending = STATE / "last-backup.json.tmp"
    pending.write_text(json.dumps(receipt, indent=2) + "\n")
    pending.replace(STATE / "last-backup.json")
    print(f"[INFO] Uploaded {name}; public-key encryption and SQLite integrity checks passed", flush=True)


def extract_verified_archive(path, directory):
    with tarfile.open(path, "r:gz") as archive:
        files = {}
        directories = set()
        seen = set()
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or str(name) in seen:
                raise RuntimeError("Unsafe or duplicate archive path")
            seen.add(str(name))
            if member.isfile():
                files[str(name)] = member
            elif member.isdir():
                if str(name) != ".":
                    directories.add(str(name))
            else:
                raise RuntimeError("Archive contains an unsupported file type")
        if not {"manifest.json", "db.sqlite3", "rsa_key.pem"} <= files.keys():
            raise RuntimeError("Archive is missing required Vaultwarden files")
        record = json.loads(archive.extractfile(files["manifest.json"]).read())
        if record["format"] != 1 or set(files) != set(record["files"]) | {"manifest.json"} or directories != set(record["directories"]):
            raise RuntimeError("Archive inventory differs from its manifest")
        directory.mkdir(mode=0o700)
        for name in sorted(directories):
            (directory / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, member in files.items():
            target = directory / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            if name != "manifest.json":
                expected = record["files"][name]
                if target.stat().st_size != expected["size"] or digest(target) != expected["sha256"]:
                    raise RuntimeError("An archived file failed its size or SHA-256 check")
        if database_counts(directory / "db.sqlite3") != record["database_counts"]:
            raise RuntimeError("Restored database counts differ from the manifest")
        return record


def restore(archive, destination, workdir):
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("Restore destination must be a new directory")
    plaintext = workdir / "backup.tar.gz"
    # Existing user keyring/card setup and local pinentry are used for recovery.
    decryption = subprocess.run(["gpg", "--batch", "--pinentry-mode", "ask", "--status-fd", "1", "--output", str(plaintext), "--decrypt", str(archive.resolve())], stdout=subprocess.PIPE, text=True)
    status = {line.split()[1] for line in decryption.stdout.splitlines() if line.startswith("[GNUPG:] ")}
    if decryption.returncode or not {"DECRYPTION_OKAY", "GOODMDC"} <= status:
        raise RuntimeError("OpenPGP decryption or integrity check failed")
    directory = workdir / "data"
    record = extract_verified_archive(plaintext, directory)
    shutil.copytree(directory, destination)
    print(f"[INFO] Decrypted and verified {len(record['files'])} files; restored database integrity passed", flush=True)
    print("[INFO] Recovery files are ready in the requested directory; stop Vaultwarden before installing them", flush=True)


def stop_on_signal(number, frame):
    # Exit through the temporary-directory context so cancellation cleans staging.
    raise SystemExit(128 + number)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("backup", "list", "fetch", "restore"), nargs="?", default="backup")
    parser.add_argument("archive", nargs="?")
    parser.add_argument("destination", nargs="?", type=Path)
    args = parser.parse_args()
    if args.operation == "fetch" and (not args.archive or not ARCHIVE_PATTERN.fullmatch(args.archive) or args.destination):
        parser.error("fetch requires an exact OpenPGP backup filename")
    if args.operation == "restore" and (not args.archive or not args.destination):
        parser.error("restore requires ARCHIVE and a new DESTINATION directory")
    if args.operation in {"backup", "list"} and (args.archive or args.destination):
        parser.error("backup and list do not take an archive or destination")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop_on_signal)
    signal.signal(signal.SIGINT, stop_on_signal)
    with tempfile.TemporaryDirectory(prefix="vaultwarden-backup-", dir="/dev/shm") as temporary:
        workdir = Path(temporary)
        if args.operation == "restore":
            restore(Path(args.archive), args.destination.absolute(), workdir)
        else:
            config = settings()
            if args.operation == "backup":
                backup(config, workdir)
            elif args.operation == "list":
                subprocess.run(rclone("lsjson", remote_directory(config), "--files-only"), check=True)
            else:
                subprocess.run(rclone("cat", remote_directory(config) + "/" + args.archive), check=True)


if __name__ == "__main__":
    main()
