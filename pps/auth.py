"""AuthModule: accounts, roles, pairing and tokens (PPS-SR-004, PPS-F-061).

Also supports PPS-SR-001 (a client must pair with the device PIN before it may
log in) and PPS-SR-005 (every authentication event is written to the audit log).

* Passwords are hashed with scrypt (stdlib) and never stored or logged.
* Roles are ordered ``trainee < analyst < admin``; :func:`require_role` enforces a minimum.
* Pairing exchanges the device PIN for a *client token*; login exchanges that token plus a
  username/password for a short-lived *access token*.
* Tokens are random and kept server-side as SHA-256 digests, so they can be revoked and
  expire on schedule. They live in memory: restarting the service invalidates them, and
  clients must pair and log in again.
* The user and role are re-read from storage on every token check, so disabling a user or
  changing a role takes effect immediately.
* Repeated failures lock out pairing (device-wide) and login (per username, whether or not
  the name exists) for ``pairing_lockout_s`` seconds. Lockout state is also in memory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .settings import Settings
from .storage import Storage

CLIENT_TOKEN_TTL_S = 30 * 24 * 3600
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128  # bounds the work an attacker can force per attempt
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
PIN_RE = re.compile(r"^[0-9]{6,12}$")
BOOTSTRAP_ADMIN = "admin"

# scrypt: ~16 MiB, tens of milliseconds. Parameters are stored in each hash so they can be
# raised later; verification refuses parameters above these bounds (a crafted hash must not
# be able to demand unbounded memory).
_N, _R, _P = 2**14, 8, 1
_MAX_N, _MAX_R, _MAX_P = 2**15, 8, 4
_SCRYPT_MAXMEM = 64 * 1024 * 1024

_MAX_TRACKED_KEYS = 1024


class AuthError(Exception):
    """Base class for authentication and authorization failures."""


class AuthenticationError(AuthError):
    """Credentials, PIN or token are missing, wrong, expired or revoked (HTTP 401)."""


class AuthorizationError(AuthError):
    """The caller is authenticated but their role is not allowed to do this (HTTP 403)."""


class LockedOutError(AuthError):
    """Too many failed attempts; try again after ``retry_after_s`` seconds (HTTP 429)."""

    def __init__(self, retry_after_s: int):
        super().__init__(f"Too many failed attempts. Try again in {retry_after_s} seconds.")
        self.retry_after_s = retry_after_s


class UserValidationError(AuthError, ValueError):
    """A username, password, role or client name is not acceptable (HTTP 400/422)."""


class UserNotFoundError(AuthError):
    """No such user (HTTP 404)."""


class LastAdminError(AuthError):
    """The change would leave the device without an active administrator (HTTP 409)."""


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    TRAINEE = "trainee"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, value: object) -> Role:
        try:
            return cls(value.lower() if isinstance(value, str) else value)
        except (ValueError, TypeError):
            allowed = ", ".join(r.value for r in cls)
            raise UserValidationError(f"role must be one of: {allowed}") from None


_RANK = {Role.TRAINEE: 0, Role.ANALYST: 1, Role.ADMIN: 2}


@dataclass(frozen=True)
class Principal:
    """An authenticated user, as established by :meth:`AuthService.authenticate_token`."""

    username: str
    role: Role


@dataclass(frozen=True)
class LoginResult:
    access_token: str
    expires_in_s: int
    username: str
    role: Role
    token_type: str = "bearer"


def require_role(principal: Principal, minimum: Role) -> None:
    """Raise :class:`AuthorizationError` unless ``principal`` has at least ``minimum``."""
    if principal.role.rank < minimum.rank:
        raise AuthorizationError(f"This action requires the {minimum.value} role.")


# ---------------------------------------------------------------- password hashing
def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def validate_password(password: object) -> str:
    if not isinstance(password, str):
        raise UserValidationError("password must be a string")
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        raise UserValidationError(
            f"password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long"
        )
    return password


def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash: ``scrypt$N$r$p$salt$hash``."""
    validate_password(password)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_SCRYPT_MAXMEM, dklen=32
    )
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check of ``password`` against a stored hash; False for any bad input."""
    try:
        scheme, n, r, p, salt, expected = (stored or "").split("$")
        n, r, p = int(n), int(r), int(p)
        if scheme != "scrypt" or n > _MAX_N or r > _MAX_R or p > _MAX_P or n < 2:
            return False
        if len(password) > MAX_PASSWORD_LEN:
            return False
        dk = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt),
            n=n,
            r=r,
            p=p,
            maxmem=_SCRYPT_MAXMEM,
            dklen=len(base64.b64decode(expected)),
        )
        return hmac.compare_digest(dk, base64.b64decode(expected))
    except (ValueError, TypeError, AttributeError):
        return False


def generate_pin() -> str:
    """A fresh 6-digit pairing PIN."""
    return f"{secrets.randbelow(10**6):06d}"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- lockout
class _AttemptLimiter:
    """Locks a key for ``window_s`` seconds after ``max_attempts`` failures within that window."""

    def __init__(self, max_attempts: int, window_s: int, clock: Callable[[], float]):
        self.max_attempts = max_attempts
        self.window_s = window_s
        self.clock = clock
        self._state: dict[str, list[float]] = {}  # key -> [failures, window_start, locked_until]

    def _live(self, key: str, now: float) -> list[float] | None:
        entry = self._state.get(key)
        if entry is None:
            return None
        lock_expired = entry[2] and entry[2] <= now
        window_expired = not entry[2] and now - entry[1] > self.window_s
        if lock_expired or window_expired:
            del self._state[key]
            return None
        return entry

    def check(self, key: str) -> None:
        now = self.clock()
        entry = self._live(key, now)
        if entry and entry[2] > now:
            raise LockedOutError(math.ceil(entry[2] - now))

    def _make_room(self, now: float) -> None:
        """Keep at most ``_MAX_TRACKED_KEYS`` entries (a hard bound, whatever the request rate).

        Expired entries go first, then the oldest *unlocked* ones; a live lockout is only
        evicted (soonest-to-expire first) when every tracked key is locked, so flooding
        with throwaway usernames cannot flush an existing lockout.
        """
        for k in list(self._state):
            self._live(k, now)
        while len(self._state) >= _MAX_TRACKED_KEYS:
            unlocked = [k for k, e in self._state.items() if not e[2]]
            if unlocked:
                del self._state[min(unlocked, key=lambda k: self._state[k][1])]
            else:
                del self._state[min(self._state, key=lambda k: self._state[k][2])]

    def failure(self, key: str) -> bool:
        """Record a failure; True if this one triggered the lockout."""
        now = self.clock()
        entry = self._live(key, now)
        if entry is None:
            if len(self._state) >= _MAX_TRACKED_KEYS:
                self._make_room(now)
            entry = self._state[key] = [0, now, 0]
        entry[0] += 1
        if entry[0] >= self.max_attempts and not entry[2]:
            entry[2] = now + self.window_s
            return True
        return False

    def success(self, key: str) -> None:
        self._state.pop(key, None)


@dataclass
class _Token:
    kind: str  # "client" | "access"
    subject: str  # client name, or username
    expires: float


class AuthService:
    """Accounts, pairing, login and authorization on top of :class:`Storage`."""

    def __init__(
        self,
        storage: Storage,
        settings: Settings | None = None,
        *,
        pin: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        cfg = settings or Settings()
        self.storage = storage
        self.token_ttl_s = cfg.token_ttl_s
        self._clock = clock
        self._lock = threading.RLock()
        self._pin = self._checked_pin(pin) if pin is not None else generate_pin()
        self._tokens: dict[str, _Token] = {}
        self._pair_limiter = _AttemptLimiter(
            cfg.pairing_lockout_attempts, cfg.pairing_lockout_s, clock
        )
        self._login_limiter = _AttemptLimiter(
            cfg.pairing_lockout_attempts, cfg.pairing_lockout_s, clock
        )
        # Verified against when the username is unknown, so response time does not reveal
        # which usernames exist.
        self._dummy_hash = hash_password(secrets.token_urlsafe(16))

    # ------------------------------------------------------------ pairing (PPS-SR-001)
    @staticmethod
    def _checked_pin(pin: str) -> str:
        if not isinstance(pin, str) or not PIN_RE.match(pin):
            raise UserValidationError("PIN must be 6-12 digits")
        return pin

    @property
    def pin(self) -> str:
        """The current pairing PIN, for display on the device only; never send it over the API."""
        return self._pin

    def rotate_pin(self, actor: Principal) -> str:
        require_role(actor, Role.ADMIN)
        with self._lock:
            self._pin = generate_pin()
        self.storage.audit(actor.username, "PAIRING_PIN_ROTATED")
        return self._pin

    def pair(self, pin: str, client_name: str) -> str:
        """Exchange the device PIN for a client token."""
        name = self._checked_client_name(client_name)
        with self._lock:
            self._pair_limiter.check("pair")
            if not isinstance(pin, str) or not hmac.compare_digest(
                pin.encode(), self._pin.encode()
            ):
                locked = self._pair_limiter.failure("pair")
                self.storage.audit("anonymous", "PAIRING_FAILED", {"client": name})
                if locked:
                    self.storage.audit("anonymous", "PAIRING_LOCKOUT", {})
                raise AuthenticationError("Invalid PIN")
            self._pair_limiter.success("pair")
            token = self._issue("client", name, CLIENT_TOKEN_TTL_S)
        self.storage.audit("anonymous", "PAIRING_OK", {"client": name})
        return token

    @staticmethod
    def _checked_client_name(name: object) -> str:
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
            raise UserValidationError("client_name must be 1-64 characters")
        if not name.isprintable():
            raise UserValidationError("client_name contains control characters")
        return name.strip()

    def validate_client(self, client_token: str | None) -> str:
        """Return the paired client's name, or raise :class:`AuthenticationError`."""
        record = self._lookup("client", client_token)
        if record is None:
            raise AuthenticationError("This client is not paired with the device")
        return record.subject

    # ------------------------------------------------------------ login (PPS-SR-004)
    def login(self, username: str, password: str, client_token: str | None) -> LoginResult:
        """Log in from a paired client; returns a short-lived access token."""
        self.validate_client(client_token)  # unpaired clients never reach password checking
        principal = self._authenticate(username, password)
        with self._lock:
            token = self._issue("access", principal.username, self.token_ttl_s)
        self.storage.audit(principal.username, "LOGIN_OK", {})
        return LoginResult(token, self.token_ttl_s, principal.username, principal.role)

    def _authenticate(
        self,
        username: object,
        password: object,
        events: tuple[str, str] = ("LOGIN_FAILED", "LOGIN_LOCKOUT"),
    ) -> Principal:
        """Check credentials, sharing one failure budget per username across all callers."""
        name = username.strip().lower()[:64] if isinstance(username, str) else ""
        key = "login:" + name
        with self._lock:
            self._login_limiter.check(key)
            user = self.storage.get_user(name) if USERNAME_RE.match(name) else None
            valid_input = isinstance(password, str)
            verified = verify_password(
                password if valid_input else "",
                user["pw_hash"] if user else self._dummy_hash,
            )
            reason = (
                "unknown_user"
                if user is None
                else "disabled"
                if not user["active"]
                else "bad_password"
                if not (verified and valid_input)
                else None
            )
            if reason:
                locked = self._login_limiter.failure(key)
                self.storage.audit(name or "anonymous", events[0], {"reason": reason})
                if locked:
                    self.storage.audit(name or "anonymous", events[1], {})
                raise AuthenticationError("Invalid username or password")
            self._login_limiter.success(key)
        return self._principal(user)

    @staticmethod
    def _principal(user: dict[str, Any]) -> Principal:
        try:
            return Principal(user["username"], Role.parse(user["role"]))
        except UserValidationError:  # unknown role in the database: deny rather than guess
            raise AuthenticationError("Invalid username or password") from None

    def authenticate_token(self, access_token: str | None) -> Principal:
        """Validate an access token; returns the user with their *current* role."""
        record = self._lookup("access", access_token)
        if record is None:
            raise AuthenticationError("Invalid or expired token")
        user = self.storage.get_user(record.subject)
        if user is None or not user["active"]:
            self._revoke_user_tokens(record.subject)
            raise AuthenticationError("Invalid or expired token")
        return self._principal(user)

    def logout(self, access_token: str | None) -> None:
        record = self._lookup("access", access_token)
        if record is not None:
            with self._lock:
                self._tokens.pop(_digest(access_token or ""), None)
            self.storage.audit(record.subject, "LOGOUT", {})

    # ------------------------------------------------------------ tokens
    def _issue(self, kind: str, subject: str, ttl_s: int) -> str:
        now = self._clock()
        for digest in [d for d, t in self._tokens.items() if t.expires <= now]:
            del self._tokens[digest]
        token = secrets.token_urlsafe(32)
        self._tokens[_digest(token)] = _Token(kind, subject, now + ttl_s)
        return token

    def _lookup(self, kind: str, token: str | None) -> _Token | None:
        if not isinstance(token, str) or not token:
            return None
        with self._lock:
            record = self._tokens.get(_digest(token))
            if record is None or record.kind != kind:
                return None
            if record.expires <= self._clock():
                del self._tokens[_digest(token)]
                return None
            return record

    def _revoke_user_tokens(self, username: str) -> None:
        with self._lock:
            for digest in [
                d for d, t in self._tokens.items() if t.kind == "access" and t.subject == username
            ]:
                del self._tokens[digest]

    # ------------------------------------------------------------ user management (PPS-F-061)
    @staticmethod
    def _checked_username(username: object) -> str:
        name = username.strip().lower() if isinstance(username, str) else ""
        if not USERNAME_RE.match(name):
            raise UserValidationError(
                "username must be 3-32 characters: lower-case letters, digits, '.', '_' or '-'"
            )
        return name

    def _require_user(self, username: str) -> dict[str, Any]:
        user = self.storage.get_user(self._checked_username(username))
        if user is None:
            raise UserNotFoundError(f"No such user: {username}")
        return user

    def _active_admins(self) -> list[str]:
        return [
            u["username"]
            for u in self.storage.list_users()
            if u["role"] == Role.ADMIN.value and u["active"]
        ]

    def create_user(self, actor: Principal, username: str, password: str, role: str) -> None:
        require_role(actor, Role.ADMIN)
        name = self._checked_username(username)
        parsed = Role.parse(role)
        pw_hash = hash_password(password)
        with self._lock:
            if self.storage.get_user(name) is not None:
                raise UserValidationError(f"User {name!r} already exists")
            self.storage.upsert_user(name, pw_hash, parsed.value, True)
        self.storage.audit(actor.username, "USER_CREATED", {"user": name, "role": parsed.value})

    def reset_password(self, actor: Principal, username: str, new_password: str) -> None:
        """Admin reset of any user's password; their existing sessions are revoked."""
        require_role(actor, Role.ADMIN)
        self._store_password(actor.username, self._require_user(username), new_password)

    def change_own_password(
        self, actor: Principal, current_password: str, new_password: str
    ) -> None:
        """Change your own password. The current one is required (and rate-limited like login)."""
        self._authenticate(
            actor.username,
            current_password,
            events=("PASSWORD_CHANGE_FAILED", "PASSWORD_CHANGE_LOCKOUT"),
        )
        self._store_password(actor.username, self._require_user(actor.username), new_password)

    def _store_password(self, actor_name: str, user: dict[str, Any], new_password: str) -> None:
        pw_hash = hash_password(new_password)
        with self._lock:
            self.storage.upsert_user(user["username"], pw_hash, user["role"], bool(user["active"]))
            self._revoke_user_tokens(user["username"])
        self.storage.audit(actor_name, "PASSWORD_CHANGED", {"user": user["username"]})

    def set_role(self, actor: Principal, username: str, role: str) -> None:
        require_role(actor, Role.ADMIN)
        parsed = Role.parse(role)
        with self._lock:
            user = self._require_user(username)
            if (
                user["role"] == Role.ADMIN.value
                and parsed is not Role.ADMIN
                and user["active"]
                and self._active_admins() == [user["username"]]
            ):
                raise LastAdminError("Cannot demote the last active administrator")
            self.storage.upsert_user(user["username"], None, parsed.value, bool(user["active"]))
        self.storage.audit(
            actor.username,
            "ROLE_CHANGED",
            {"user": user["username"], "from": user["role"], "to": parsed.value},
        )

    def set_active(self, actor: Principal, username: str, active: bool) -> None:
        require_role(actor, Role.ADMIN)
        with self._lock:
            user = self._require_user(username)
            if (
                not active
                and user["role"] == Role.ADMIN.value
                and user["active"]
                and self._active_admins() == [user["username"]]
            ):
                raise LastAdminError("Cannot disable the last active administrator")
            self.storage.upsert_user(user["username"], None, user["role"], bool(active))
            if not active:
                self._revoke_user_tokens(user["username"])
        self.storage.audit(
            actor.username,
            "USER_ENABLED" if active else "USER_DISABLED",
            {"user": user["username"]},
        )

    def bootstrap_admin(self) -> str | None:
        """On first run (no users) create ``admin`` with a random password and return it.

        Returns ``None`` if users already exist. The password is shown once and is not stored
        in plaintext anywhere.
        """
        with self._lock:
            if self.storage.user_count():
                return None
            password = secrets.token_urlsafe(12)
            self.storage.upsert_user(BOOTSTRAP_ADMIN, hash_password(password), "admin", True)
        self.storage.audit("system", "USER_CREATED", {"user": BOOTSTRAP_ADMIN, "role": "admin"})
        return password
