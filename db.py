"""
db.py – MySQL persistence layer for the Searchable Encryption Demo
Requires: pip install mysql-connector-python
"""

import os
import hashlib
from typing import List, Dict, Optional

import mysql.connector
from mysql.connector import Error


# ── Connection ─────────────────────────────────────────────────────────────────

def get_connection():
    """
    Return a live MySQL connection with hardcoded credentials.
    """
    return mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="root@2026",
        database="searchable_enc",
        autocommit=True,
    )


# ── Schema ─────────────────────────────────────────────────────────────────────

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        session_key   VARCHAR(64)  NOT NULL UNIQUE,
        mode          VARCHAR(64)  NOT NULL,
        created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_session_key (session_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS encrypted_documents (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        session_id        INT          NOT NULL,
        doc_index         INT          NOT NULL,
        encrypted_content MEDIUMTEXT   NOT NULL,
        created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
        UNIQUE KEY uq_session_doc (session_id, doc_index)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS keyword_index (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        session_id    INT          NOT NULL,
        keyword_hash  VARCHAR(128) NOT NULL,
        doc_index     INT          NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
        INDEX idx_kw (session_id, keyword_hash)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS search_log (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        session_id    INT          NOT NULL,
        trapdoor      VARCHAR(128) NOT NULL,
        results_count INT          NOT NULL DEFAULT 0,
        searched_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pattern_words (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        session_id    INT          NOT NULL,
        word          VARCHAR(255) NOT NULL,
        ciphertext    TEXT         NOT NULL,
        position      INT          NOT NULL,
        created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    )
    """,
]


def init_db() -> tuple[bool, str]:
    """Create all tables if they don't exist. Call once at app startup."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        for stmt in _SCHEMA:
            cursor.execute(stmt)
        cursor.close()
        conn.close()
        return True, "Database initialised successfully."
    except Error as e:
        return False, f"DB init error: {e}"


# ── Session helpers ────────────────────────────────────────────────────────────

def _session_key(master_key: bytes) -> str:
    """Derive a stable, non-reversible identifier from the master key."""
    return hashlib.sha256(master_key).hexdigest()


def upsert_session(master_key: bytes, mode: str) -> Optional[int]:
    """Insert (or look up) a session row. Returns session.id or None on error."""
    sk = _session_key(master_key)
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (session_key, mode) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE mode = VALUES(mode)",
            (sk, mode),
        )
        cursor.execute("SELECT id FROM sessions WHERE session_key = %s", (sk,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row[0] if row else None
    except Error:
        return None


def get_all_sessions() -> List[Dict]:
    """Return all sessions ordered newest-first."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, session_key, mode, created_at "
            "FROM sessions ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error:
        return []


# ── Encrypted documents ────────────────────────────────────────────────────────

def save_encrypted_docs(session_id: int, encrypted_docs: List[Dict]) -> bool:
    """
    Persist encrypted document dicts produced by SSEWithIndex.build_index().
    Replaces any existing documents for this session.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM encrypted_documents WHERE session_id = %s", (session_id,)
        )
        rows = [
            (session_id, doc["doc_id"], doc["encrypted_content"])
            for doc in encrypted_docs
        ]
        cursor.executemany(
            "INSERT INTO encrypted_documents (session_id, doc_index, encrypted_content) "
            "VALUES (%s, %s, %s)",
            rows,
        )
        cursor.close()
        conn.close()
        return True
    except Error:
        return False


def load_encrypted_docs(session_id: int) -> List[Dict]:
    """Load encrypted documents for a session, in index order."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT doc_index AS doc_id, encrypted_content "
            "FROM encrypted_documents WHERE session_id = %s ORDER BY doc_index",
            (session_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error:
        return []


# ── Keyword index ──────────────────────────────────────────────────────────────

def save_keyword_index(session_id: int, index: Dict[str, set]) -> bool:
    """
    Persist the SSE inverted index {keyword_hash -> set(doc_ids)}.
    Replaces any existing index entries for this session.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM keyword_index WHERE session_id = %s", (session_id,)
        )
        rows = [
            (session_id, kh, doc_id)
            for kh, doc_ids in index.items()
            for doc_id in doc_ids
        ]
        if rows:
            cursor.executemany(
                "INSERT INTO keyword_index (session_id, keyword_hash, doc_index) "
                "VALUES (%s, %s, %s)",
                rows,
            )
        cursor.close()
        conn.close()
        return True
    except Error:
        return False


def load_keyword_index(session_id: int) -> Dict[str, set]:
    """Reconstruct the inverted index dict from the DB."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT keyword_hash, doc_index FROM keyword_index WHERE session_id = %s",
            (session_id,),
        )
        index: Dict[str, set] = {}
        for kh, doc_id in cursor.fetchall():
            index.setdefault(kh, set()).add(doc_id)
        cursor.close()
        conn.close()
        return index
    except Error:
        return {}


# ── Search log ─────────────────────────────────────────────────────────────────

def log_search(session_id: int, trapdoor: str, results_count: int) -> bool:
    """Record a search event. Only the trapdoor is stored — no plaintext keyword."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO search_log (session_id, trapdoor, results_count) "
            "VALUES (%s, %s, %s)",
            (session_id, trapdoor, results_count),
        )
        cursor.close()
        conn.close()
        return True
    except Error:
        return False


def get_search_history(session_id: int) -> List[Dict]:
    """Return the 50 most recent searches for a session."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT trapdoor, results_count, searched_at "
            "FROM search_log WHERE session_id = %s "
            "ORDER BY searched_at DESC LIMIT 50",
            (session_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error:
        return []


# ── Pattern words (deterministic encryption mode) ──────────────────────────────

def save_pattern_words(
    session_id: int, words: List[str], enc_results: List[Dict]
) -> bool:
    """Save word→ciphertext pairs from the deterministic encryption demo."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM pattern_words WHERE session_id = %s", (session_id,)
        )
        rows = [
            (session_id, word, enc["ciphertext"], pos)
            for pos, (word, enc) in enumerate(zip(words, enc_results))
        ]
        cursor.executemany(
            "INSERT INTO pattern_words (session_id, word, ciphertext, position) "
            "VALUES (%s, %s, %s, %s)",
            rows,
        )
        cursor.close()
        conn.close()
        return True
    except Error:
        return False


def load_pattern_words(session_id: int) -> List[Dict]:
    """Load pattern words for a session, in original order."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT word, ciphertext, position FROM pattern_words "
            "WHERE session_id = %s ORDER BY position",
            (session_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error:
        return []


# ── Global stats ───────────────────────────────────────────────────────────────

def get_global_stats() -> Dict:
    """Aggregate counts across all sessions for the sidebar dashboard."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM sessions)            AS total_sessions,
                (SELECT COUNT(*) FROM encrypted_documents) AS total_docs,
                (SELECT COUNT(*) FROM keyword_index)       AS total_index_entries,
                (SELECT COUNT(*) FROM search_log)          AS total_searches
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row or {}
    except Error:
        return {}