# Maxwell License 1.0
# Copyright (c) 2026 Maxwell
# Distributed under the Maxwell License 1.0

import os
import sys
import io
import json
import re
import sqlite3
import shutil
import tempfile
import threading
import logging
from datetime import datetime
from typing import List, Optional
import uuid

# Paths and app metadata 
HOME = os.path.expanduser("~")
APP_NAME = "MaxNote"
APP_VERSION = "1.3.5"
APP_ROOT = os.path.join(HOME, ".local", "share", APP_NAME)
DATA_DIR = os.path.join(APP_ROOT, "data")
LOG_DIR = os.path.join(APP_ROOT, "logs")
EXPORTS_DIR = os.path.join(APP_ROOT, "exports")
ATTACH_DIR = os.path.join(DATA_DIR, "attachments")
ASSETS_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets")
FONTS_DIR = os.path.join(ASSETS_DIR, "fonts")
ICONS_DIR = os.path.join(ASSETS_DIR, "icons")
BUILD_DIR = os.path.join(APP_ROOT, "build")
FILTERS_PATH = os.path.join(APP_ROOT, "saved_filters.json")
TEMPLATES_LOCAL_PATH = os.path.join(APP_ROOT, "local_templates.json")
PRESETS_PATH = os.path.join(EXPORTS_DIR, "presets.json")
SETTINGS_PATH = os.path.join(APP_ROOT, "settings.json")

for p in (DATA_DIR, LOG_DIR, EXPORTS_DIR, ATTACH_DIR, ASSETS_DIR, FONTS_DIR, ICONS_DIR, BUILD_DIR):
    os.makedirs(p, exist_ok=True)

LOG_PATH = os.path.join(LOG_DIR, "backend.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("maxnote")

# Optional libraries
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except Exception:
    TESSERACT_AVAILABLE = False

# Optional cryptography for encryption
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    import base64
    import secrets
    CRYPTO_AVAILABLE = True
except Exception:
    PBKDF2HMAC = None
    Fernet = None
    base64 = None
    secrets = None
    CRYPTO_AVAILABLE = False

def _derive_key(password: str, salt: Optional[bytes] = None, iterations: int = 200_000):
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography required for encryption")
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key, salt

def encrypt_bytes_with_password(plaintext: bytes, password: str) -> bytes:
    key, salt = _derive_key(password)
    token = Fernet(key).encrypt(plaintext)
    return salt + token

def decrypt_bytes_with_password(blob: bytes, password: str) -> bytes:
    if len(blob) < 17:
        raise ValueError("Invalid blob")
    salt = blob[:16]
    token = blob[16:]
    key, _ = _derive_key(password, salt=salt)
    return Fernet(key).decrypt(token)

# Database (SQLAlchemy) 
try:
    from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, select, Boolean
    from sqlalchemy.orm import sessionmaker, declarative_base
except Exception:
    raise RuntimeError("SQLAlchemy required: pip install SQLAlchemy")

DB_PATH = os.path.join(DATA_DIR, "notes.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, future=True)
SessionLocal = sessionmaker(bind=engine, future=True)
Base = declarative_base()


class NoteModel(Base):
    __tablename__ = "notes"
    id = Column(String(36), primary_key=True)
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    attachments = Column(Text, nullable=True)
    spans = Column(Text, nullable=True)
    ocr_text = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    version = Column(Integer, default=1)
    dirty = Column(Boolean, default=False)


class TemplateModel(Base):
    __tablename__ = "templates"
    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    body = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(notes);")
        cols = [r[1] for r in cur.fetchall()]
        if "tags" not in cols:
            cur.execute("ALTER TABLE notes ADD COLUMN tags TEXT;")
            conn.commit()
        if "attachments" not in cols:
            cur.execute("ALTER TABLE notes ADD COLUMN attachments TEXT;")
            conn.commit()
        if "spans" not in cols:
            cur.execute("ALTER TABLE notes ADD COLUMN spans TEXT;")
            conn.commit()
        if "ocr_text" not in cols:
            cur.execute("ALTER TABLE notes ADD COLUMN ocr_text TEXT;")
            conn.commit()
        cur.close()
        conn.close()
    except Exception:
        logger.exception("DB migration check failed (non-fatal)")

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notes_fts';")
        if not cur.fetchone():
            cur.execute("""
                CREATE VIRTUAL TABLE notes_fts USING fts5(
                    title, body, tags, ocr_text, content='notes', content_rowid='rowid'
                );
            """)
            cur.execute("INSERT INTO notes_fts(rowid, title, body, tags, ocr_text) SELECT rowid, title, body, tags, ocr_text FROM notes;")
            conn.commit()
        cur.close()
        conn.close()
    except Exception:
        logger.exception("Failed to ensure FTS index (non-fatal)")


def fts_upsert_note_row_by_id(note_id: str) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT rowid, title, body, tags, ocr_text FROM notes WHERE id = ?", (note_id,))
        r = cur.fetchone()
        if not r:
            return
        rowid, title, body, tags, ocr_text = r
        cur.execute("DELETE FROM notes_fts WHERE rowid = ?", (rowid,))
        cur.execute("INSERT INTO notes_fts(rowid, title, body, tags, ocr_text) VALUES (?, ?, ?, ?, ?)",
                    (rowid, title or "", body or "", tags or "", ocr_text or ""))
        conn.commit()
    except Exception:
        logger.exception("Failed to upsert FTS row for note %s", note_id)
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


def fts_delete_row_by_id(note_id: str) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT rowid FROM notes WHERE id = ?", (note_id,))
        r = cur.fetchone()
        if not r:
            return
        rowid = r[0]
        cur.execute("DELETE FROM notes_fts WHERE rowid = ?", (rowid,))
        conn.commit()
    except Exception:
        logger.exception("Failed to delete FTS row for note %s", note_id)
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


# PDF export helper 
def sanitize_filename(name: str) -> str:
    s = (name or "").strip()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^A-Za-z0-9\-_]", "", s)
    s = s.strip("-_")
    return s or "maxnote"


def json_to_pdf_bytes_with_assets(data: dict, include_assets: bool = True) -> bytes:
    title = data.get("title", APP_NAME)
    rows = data.get("rows", [{"content": ""}])
    content = rows[0].get("content", "")
    attachments = data.get("attachments", []) or []
    buf = io.BytesIO()
    if not REPORTLAB_AVAILABLE:
        buf.write(content.encode("utf-8"))
        buf.seek(0)
        return buf.read()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    try:
        if os.path.isdir(FONTS_DIR):
            fonts = [f for f in os.listdir(FONTS_DIR) if f.lower().endswith((".ttf", ".otf"))]
            if fonts:
                try:
                    font_path = os.path.join(FONTS_DIR, fonts[0])
                    font_name = os.path.splitext(fonts[0])[0]
                    pdfmetrics.registerFont(TTFont(font_name, font_path))
                    styles["Normal"].fontName = font_name
                    styles["Title"].fontName = font_name
                except Exception:
                    pass
    except Exception:
        pass
    flow = []
    flow.append(Paragraph(title, styles["Title"]))
    flow.append(Spacer(1, 12))
    flow.append(Paragraph(content.replace("\n", "<br/>"), styles["Normal"]))
    flow.append(Spacer(1, 12))
    for att in attachments:
        try:
            path = att.get("path")
            if path and os.path.exists(path) and os.path.splitext(path)[1].lower() in (".png", ".jpg", ".jpeg", ".gif"):
                fname = os.path.basename(path)
                flow.append(PageBreak())
                flow.append(Paragraph(f"Attachment: {fname}", styles["Normal"]))
                flow.append(Spacer(1, 6))
                flow.append(Image(path, width=400, height=300))
                flow.append(Spacer(1, 12))
        except Exception:
            logger.debug("Failed to embed attachment %s", att)
    if include_assets:
        images_dir = os.path.join(ASSETS_DIR, "images")
        if os.path.isdir(images_dir):
            for fname in sorted(os.listdir(images_dir)):
                if fname.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
                    path = os.path.join(images_dir, fname)
                    try:
                        flow.append(PageBreak())
                        flow.append(Paragraph(f"Image: {fname}", styles["Normal"]))
                        flow.append(Spacer(1, 6))
                        flow.append(Image(path, width=400, height=300))
                        flow.append(Spacer(1, 12))
                    except Exception:
                        logger.debug("Failed to embed asset image %s", path)
    doc.build(flow)
    buf.seek(0)
    return buf.read()


def write_note_pdf_to_exports(note_id: str, title: str, body: str, attachments: list, include_assets: bool = True) -> str:
    """
    Create a PDF for the given note and write it to EXPORTS_DIR.
    Returns the final path on success.
    """
    try:
        payload = {"title": title or APP_NAME, "rows": [{"content": body or ""}], "attachments": attachments or []}
        pdf_bytes = json_to_pdf_bytes_with_assets(payload, include_assets=include_assets)
        fname = sanitize_filename(title or note_id) + f"_{note_id[:8]}.pdf"
        final = os.path.join(EXPORTS_DIR, fname)
        # write atomically to temp then move
        fd, tmp = tempfile.mkstemp(suffix=".pdf", dir=EXPORTS_DIR)
        os.close(fd)
        with open(tmp, "wb") as f:
            f.write(pdf_bytes)
            f.flush()
            os.fsync(f.fileno())
        try:
            shutil.move(tmp, final)
        except Exception:
            try:
                os.replace(tmp, final)
            except Exception:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                raise
        return final
    except Exception:
        logger.exception("Failed to write note PDF for %s", note_id)
        raise


# FastAPI optional backend
try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Query, Body
    from fastapi.responses import StreamingResponse
    from pydantic import BaseModel
except Exception:
    FastAPI = None
    HTTPException = Exception
    UploadFile = None
    File = None
    Query = None
    Body = None
    StreamingResponse = None
    BaseModel = object

app_post_upload_attachment_available: bool = FastAPI is not None and UploadFile is not None

if FastAPI:
    app = FastAPI(title=f"{APP_NAME} Backend")

    class AttachmentSchema(BaseModel):
        id: Optional[str]
        filename: Optional[str]
        path: Optional[str]
        position: Optional[int] = None
        type: Optional[str] = None

    class NoteIn(BaseModel):
        title: str
        body: Optional[str] = ""
        tags: Optional[List[str]] = []
        attachments: Optional[List[AttachmentSchema]] = []
        spans: Optional[List[dict]] = None
        version: Optional[int] = None

    class TemplateIn(BaseModel):
        name: str
        body: Optional[str] = ""

    @app.on_event("startup")
    def startup_event() -> None:
        init_db()
        logger.info("Backend ready. DB at %s", DB_PATH)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": APP_VERSION}

    @app.post("/notes")
    async def create_note(payload: NoteIn) -> dict:
        session = SessionLocal()
        try:
            now = datetime.utcnow()
            note = NoteModel(
                id=str(uuid.uuid4()),
                title=payload.title,
                body=payload.body,
                tags=json.dumps(payload.tags) if payload.tags else "[]",
                attachments=json.dumps([a.dict() for a in payload.attachments]) if payload.attachments else "[]",
                spans=json.dumps(payload.spans) if payload.spans else "[]",
                ocr_text="",
                created_at=now,
                updated_at=now,
                version=1,
                dirty=False,
            )
            session.add(note)
            session.commit()
            session.refresh(note)
            fts_upsert_note_row_by_id(note.id)
            return {"id": note.id, "version": note.version}
        except Exception:
            logger.exception("Failed to create note")
            raise HTTPException(status_code=500, detail="Failed to create note")
        finally:
            session.close()

    @app.put("/notes/{note_id}")
    async def update_note(note_id: str, payload: dict = Body(...)) -> dict:
        session = SessionLocal()
        try:
            note = session.get(NoteModel, note_id)
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            client_version = payload.get("version")
            if client_version and client_version != note.version:
                raise HTTPException(status_code=409, detail="Version conflict")
            note.title = payload.get("title", note.title)
            note.body = payload.get("body", note.body)
            if payload.get("tags") is not None:
                note.tags = json.dumps(payload.get("tags", []))
            if payload.get("attachments") is not None:
                note.attachments = json.dumps(payload.get("attachments"))
            if payload.get("spans") is not None:
                note.spans = json.dumps(payload.get("spans"))
            if payload.get("ocr_text") is not None:
                note.ocr_text = payload.get("ocr_text")
            note.version = (note.version or 1) + 1
            note.updated_at = datetime.utcnow()
            note.dirty = False
            session.commit()
            fts_upsert_note_row_by_id(note.id)
            return {"id": note.id, "version": note.version}
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to update note")
            raise HTTPException(status_code=500, detail="Failed to update note")
        finally:
            session.close()

    @app.delete("/notes/{note_id}")
    async def delete_note(note_id: str) -> dict:
        session = SessionLocal()
        try:
            note = session.get(NoteModel, note_id)
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            try:
                attachments = json.loads(note.attachments) if note.attachments else []
                for att in attachments:
                    if isinstance(att, dict) and att.get("path"):
                        try:
                            os.remove(att["path"])
                        except Exception:
                            pass
            except Exception:
                pass
            session.delete(note)
            session.commit()
            fts_delete_row_by_id(note_id)
            return {"status": "deleted"}
        except Exception:
            logger.exception("Failed to delete note")
            raise HTTPException(status_code=500, detail="Failed to delete note")
        finally:
            session.close()

    @app.get("/notes")
    async def list_notes(
        q: Optional[str] = Query(None),
        tags: Optional[str] = Query(None),
        has: Optional[str] = Query(None)
    ) -> List[dict]:
        session = SessionLocal()
        try:
            stmt = select(NoteModel).order_by(NoteModel.updated_at.desc().nullslast())
            res = session.execute(stmt).scalars().all()
            out: List[dict] = []
            for n in res:
                try:
                    note_tags = json.loads(n.tags) if n.tags else []
                except Exception:
                    note_tags = []
                try:
                    attachments = json.loads(n.attachments) if n.attachments else []
                except Exception:
                    attachments = []
                try:
                    spans = json.loads(n.spans) if n.spans else []
                except Exception:
                    spans = []
                if q:
                    if q.lower() not in (n.title or "").lower() and q.lower() not in (n.body or "").lower() and q.lower() not in (n.ocr_text or "").lower():
                        continue
                if tags:
                    wanted = [t.strip().lower() for t in tags.split(",") if t.strip()]
                    if not any(w in [tt.lower() for tt in note_tags] for w in wanted):
                        continue
                if has == "image":
                    if not any(isinstance(a, dict) and a.get("type", "").startswith("image") for a in attachments):
                        continue
                out.append({
                    "id": n.id,
                    "title": n.title,
                    "body": n.body,
                    "tags": note_tags,
                    "attachments": attachments,
                    "spans": spans,
                    "ocr_text": n.ocr_text or "",
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                    "updated_at": n.updated_at.isoformat() if n.updated_at else None,
                    "version": n.version,
                })
            return out
        finally:
            session.close()

    @app.get("/notes/{note_id}")
    async def get_note(note_id: str) -> dict:
        session = SessionLocal()
        try:
            note = session.get(NoteModel, note_id)
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            try:
                attachments = json.loads(note.attachments) if note.attachments else []
            except Exception:
                attachments = []
            try:
                spans = json.loads(note.spans) if note.spans else []
            except Exception:
                spans = []
            try:
                tags = json.loads(note.tags) if note.tags else []
            except Exception:
                tags = []
            return {
                "id": note.id,
                "title": note.title,
                "body": note.body,
                "tags": tags,
                "attachments": attachments,
                "spans": spans,
                "ocr_text": note.ocr_text or "",
                "created_at": note.created_at.isoformat() if note.created_at else None,
                "updated_at": note.updated_at.isoformat() if note.updated_at else None,
                "version": note.version,
            }
        finally:
            session.close()

    if app_post_upload_attachment_available:
        @app.post("/notes/{note_id}/attachments")
        async def upload_attachment(note_id: str, file: UploadFile = File(...)) -> dict: # pyright: ignore[reportInvalidTypeForm]
            session = SessionLocal()
            try:
                note = session.get(NoteModel, note_id)
                if not note:
                    raise HTTPException(status_code=404, detail="Note not found")
                att_id = str(uuid.uuid4())
                filename = f"{att_id}_{os.path.basename(file.filename)}"
                attach_dir = os.path.join(ATTACH_DIR, note_id)
                os.makedirs(attach_dir, exist_ok=True)
                dest = os.path.join(attach_dir, filename)
                content = await file.read()
                with open(dest, "wb") as f:
                    f.write(content)
                try:
                    attachments = json.loads(note.attachments) if note.attachments else []
                except Exception:
                    attachments = []
                att_meta = {"id": att_id, "filename": filename, "path": dest, "type": file.content_type}
                attachments.append(att_meta)
                note.attachments = json.dumps(attachments)
                note.updated_at = datetime.utcnow()
                session.commit()
                threading.Thread(target=ocr_worker, args=(note_id, dest), daemon=True).start()
                fts_upsert_note_row_by_id(note_id)
                return att_meta
            except Exception:
                logger.exception("Attachment upload failed")
                raise HTTPException(status_code=500, detail="Attachment upload failed")
            finally:
                session.close()

    @app.get("/search")
    async def search_notes(q: str = Query(...), limit: int = 25, offset: int = 0) -> List[dict]:
        if not q:
            return []
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            fts_query = q
            cur.execute("SELECT rowid, title, body, tags FROM notes_fts WHERE notes_fts MATCH ? LIMIT ? OFFSET ?", (fts_query, limit, offset))
            rows = cur.fetchall()
            out: List[dict] = []
            for row in rows:
                rowid, title, body, tags_json = row
                cur2 = conn.cursor()
                cur2.execute("SELECT id, updated_at FROM notes WHERE rowid = ?", (rowid,))
                r2 = cur2.fetchone()
                if not r2:
                    continue
                note_id, updated_at = r2
                try:
                    tags = json.loads(tags_json) if tags_json else []
                except Exception:
                    tags = []
                out.append({"id": note_id, "title": title, "body": body, "tags": tags, "updated_at": updated_at, "score": None})
            return out
        except Exception:
            logger.exception("Search failed")
            raise HTTPException(status_code=500, detail="Search failed")
        finally:
            cur.close()
            conn.close()

    @app.post("/export/pdf")
    async def export_pdf_endpoint(payload: dict, include_assets: bool = Query(False)):
        try:
            pdf_bytes = json_to_pdf_bytes_with_assets(payload, include_assets)
            filename = sanitize_filename(payload.get("title", APP_NAME)) + ".pdf"
            return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf",
                                     headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        except Exception:
            logger.exception("PDF generation failed")
            raise HTTPException(status_code=500, detail="PDF generation failed")


# OCR worker 
def ocr_worker(note_id: str, file_path: str) -> None:
    try:
        if not TESSERACT_AVAILABLE or not PIL_AVAILABLE:
            logger.debug("Tesseract or Pillow not available; skipping OCR")
            return
        if not file_path.lower().endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif")):
            return
        img = Image.open(file_path)
        text = pytesseract.image_to_string(img)
        if not text.strip():
            return
        s = SessionLocal()
        try:
            note = s.get(NoteModel, note_id)
            if note:
                existing = note.ocr_text or ""
                combined = (existing + "\n" + text).strip() if existing else text.strip()
                note.ocr_text = combined
                note.updated_at = datetime.utcnow()
                s.commit()
                fts_upsert_note_row_by_id(note_id)
                logger.info("OCR appended for note %s (file %s)", note_id, file_path)
        finally:
            s.close()
    except Exception:
        logger.exception("OCR worker failed for %s", file_path)


# Background executor for GUI 
from concurrent.futures import ThreadPoolExecutor
_BG_EXECUTOR = ThreadPoolExecutor(max_workers=4)


def run_in_background(fn, on_done=None):
    future = _BG_EXECUTOR.submit(fn)

    def _cb(fut):
        try:
            res = fut.result()
        except Exception as e:
            res = e
        if on_done:
            try:
                root = globals().get("app_ui") or None
                if root:
                    root.after(0, lambda: on_done(res))
                else:
                    on_done(res)
            except Exception:
                on_done(res)

    future.add_done_callback(_cb)
    return future


# GUI (Tkinter) 
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    import tkinter.font as tkfont
except Exception as e:
    logger.exception("Frontend import failed: %s", e)
    raise RuntimeError("Frontend dependencies missing (tkinter).") from e

# UI customization data and helpers 
THEMES = [
    "Minimal White", "Sepia", "Dark", "Solarized Light", "Solarized Dark",
    "Monokai", "Nord", "Gruvbox", "High Contrast", "Soft Pastel"
]

FONT_FAMILIES = [
    "Segoe UI", "Arial", "Helvetica", "Verdana", "Tahoma",
    "Times New Roman", "Georgia", "Courier New", "Liberation Sans", "DejaVu Sans"
]

FONT_SIZES = [10, 11, 12, 13, 14, 16, 18, 20, 22, 24]

# Base icon size (previously 18). Increase by 5% as requested.
ICON_BASE_SIZE = 18
ICON_SIZE = max(1, int(round(ICON_BASE_SIZE * 1.05)))  # 19

_ICON_EMOJI = {
    "new": "🆕",
    "open": "📂",
    "info": "ℹ️",
    "save": "💾",
    "saveas": "💾",
    "export": "📤",
    "encrypt": "🔒",
    "decrypt": "🔓",
    "bold": "𝐁",
    "italic": "𝑰",
    "underline": "U̲",
    "refresh": "🔄",
    "delete": "🗑️",
}

def load_icon(name: str, size: int = ICON_SIZE):
    try:
        if not PIL_AVAILABLE:
            return None
        path = os.path.join(ICONS_DIR, f"{name}.png")
        if os.path.exists(path):
            img = Image.open(path)
            img = img.resize((size, size), Image.LANCZOS)
            return ImageTk.PhotoImage(img)
    except Exception:
        logger.debug("Failed to load icon %s", name)
    return None

def make_icon_button(parent, name: str, command, tooltip: Optional[str] = None):
    icon = load_icon(name, size=ICON_SIZE)
    if icon:
        btn = ttk.Button(parent, image=icon, command=command)
        btn.image = icon
    else:
        glyph = _ICON_EMOJI.get(name, name[:1])
        btn = ttk.Button(parent, text=glyph, width=3, command=command)
    if tooltip:
        try:
            btn.tooltip_text = tooltip
        except Exception:
            pass
    return btn

# Persistent settings 
DEFAULT_SETTINGS = {
    "theme": "Sepia",
    "font_family": "Segoe UI",
    "font_size": 12,
    "autosave_interval_s": 10,
    "last_opened_note": None,
    # encryption settings stored here
    "use_stored_password": False,
    "encryption_password": ""
}

def load_settings() -> dict:
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for k, v in DEFAULT_SETTINGS.items():
                        data.setdefault(k, v)
                    return data
    except Exception:
        logger.exception("Failed to load settings")
    return DEFAULT_SETTINGS.copy()

def save_settings(settings: dict) -> None:
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Failed to save settings")


# Helpers for spans and offsets 
def index_to_offset(text: str, index: str) -> int:
    try:
        line, col = index.split(".")
        line = int(line)
        col = int(col)
    except Exception:
        return 0
    lines = text.splitlines(True)
    if line <= 1:
        return col
    acc = 0
    for i in range(line - 1):
        acc += len(lines[i])
    return acc + col

def offset_to_index(text: str, offset: int) -> str:
    if offset <= 0:
        return "1.0"
    lines = text.splitlines(True)
    acc = 0
    for i, ln in enumerate(lines):
        ln_len = len(ln)
        if acc + ln_len > offset:
            col = offset - acc
            return f"{i+1}.{col}"
        acc += ln_len
    last_line = len(lines)
    if last_line == 0:
        return "1.0"
    return f"{last_line}.{max(0, len(lines[-1]))}"

def collect_spans_from_widget(text_widget) -> List[dict]:
    content = text_widget.get("1.0", "end-1c")
    spans = []
    for tag_name in ("bold", "italic", "underline"):
        try:
            ranges = text_widget.tag_ranges(tag_name)
            for i in range(0, len(ranges), 2):
                start_idx = str(ranges[i])
                end_idx = str(ranges[i + 1])
                start_off = index_to_offset(content, start_idx)
                end_off = index_to_offset(content, end_idx)
                if end_off > start_off:
                    spans.append({"type": tag_name, "start": start_off, "end": end_off})
        except Exception:
            continue
    return spans


# Main UI class 
class MaxNoteUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.title(f"{APP_NAME} — {APP_VERSION}")
        self.geometry("1200x760")
        self.minsize(1000, 640)
        self._current_note_id = None
        self._current_version = None
        self._current_attachments = []
        self._tag_list = []
        self._all_notes = []
        self.create_menu()
        self.create_layout()
        self.apply_persisted_settings()
        self.after(200, self.load_notes)
        self.bind_all("<Control-s>", lambda e: (self.save_note(), "break"))
        self.bind_all("<Control-Shift-S>", lambda e: (self.save_as(), "break"))
        self.bind_all("<Control-e>", lambda e: (self.export_pdf(), "break"))
        self.bind_all("<Control-b>", lambda e: (self.toggle_bold(), "break"))
        self.bind_all("<Control-i>", lambda e: (self.toggle_italic(), "break"))
        self.bind_all("<Control-u>", lambda e: (self.toggle_underline(), "break"))

    # Menu 
    def create_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New", command=self.new_note)
        file_menu.add_command(label="Open", command=self.open_file_dialog)
        file_menu.add_command(label="Save", command=self.save_note)
        file_menu.add_command(label="Save As", command=self.save_as)
        file_menu.add_separator()
        file_menu.add_command(label="Export PDF", command=self.export_pdf)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        theme_menu = tk.Menu(view_menu, tearoff=0)
        for t in THEMES:
            theme_menu.add_radiobutton(label=t, command=lambda tt=t: self._set_theme(tt))
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        # Settings menu to the right of Help (stores encryption/decryption preferences)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Encryption Settings", command=self.open_settings_dialog)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        self.config(menu=menubar)

    def show_about(self):
        messagebox.showinfo(f"About {APP_NAME}", f"{APP_NAME}\nVersion: {APP_VERSION}\nDistributed under Maxwell License 1.0")

    # Settings dialog (stores encryption/decryption prefs) 
    def open_settings_dialog(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("420x200")
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Encryption Settings", font=(self.settings.get("font_family", "Segoe UI"), 11, "bold")).pack(anchor="w", pady=(0,8))

        use_var = tk.BooleanVar(value=bool(self.settings.get("use_stored_password", False)))
        ttk.Checkbutton(frm, text="Use stored password for encrypt/decrypt", variable=use_var).pack(anchor="w", pady=(0,6))

        ttk.Label(frm, text="Stored encryption password (optional):").pack(anchor="w")
        pwd_var = tk.StringVar(value=self.settings.get("encryption_password", ""))
        pwd_entry = ttk.Entry(frm, textvariable=pwd_var, show="*")
        pwd_entry.pack(fill="x", pady=(0,8))

        note = ttk.Label(frm, text="Note: storing passwords in settings is not encrypted. Use at your own risk.", foreground="#a00")
        note.pack(anchor="w", pady=(0,8))

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(6,0))
        def _save_settings():
            self.settings["use_stored_password"] = bool(use_var.get())
            self.settings["encryption_password"] = pwd_var.get() or ""
            save_settings(self.settings)
            messagebox.showinfo("Settings", "Settings saved.")
            win.destroy()
        def _clear_password():
            pwd_var.set("")
        ttk.Button(btns, text="Save", command=_save_settings).pack(side="right", padx=(6,0))
        ttk.Button(btns, text="Clear Password", command=_clear_password).pack(side="right")

    # Layout 
    def create_layout(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        status_bar.pack(side="bottom", fill="x")

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=6, pady=6)

        left = ttk.Frame(main, width=320)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        search_frame = ttk.Frame(left)
        search_frame.pack(fill="x", padx=8, pady=(6, 0))
        self.search_var = tk.StringVar()
        ttk.Label(search_frame, text="Search:").pack(side="left")
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        search_entry.bind("<KeyRelease>", lambda e: self._on_search_change())

        self.listbox = tk.Listbox(left)
        self.listbox.pack(fill="both", expand=True, padx=8, pady=6)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        left_btns = ttk.Frame(left)
        left_btns.pack(fill="x", padx=8, pady=6)
        # Buttons removed per request (no New/Refresh/Delete buttons visible)
        # Bring back Refresh and Delete icons at the bottom left corner
        make_icon_button(left_btns, "refresh", self.load_notes, tooltip="Refresh").pack(side="left", padx=2)
        make_icon_button(left_btns, "delete", self.delete_current_note, tooltip="Delete selected note").pack(side="left", padx=2)

        center = ttk.Frame(main)
        center.pack(side="left", fill="both", expand=True, padx=6)

        title_frame = ttk.Frame(center)
        title_frame.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(title_frame, text="Title:").pack(side="left")
        self.title_var = tk.StringVar()
        ttk.Entry(title_frame, textvariable=self.title_var, font=(self.settings.get("font_family", "Segoe UI"), 14)).pack(side="left", fill="x", expand=True, padx=(6, 0))

        # Under the Title Bar only Bold, Italic and Underline icons remain
        format_icons_frame = ttk.Frame(title_frame)
        format_icons_frame.pack(side="left", padx=(12, 0))
        make_icon_button(format_icons_frame, "bold", self.toggle_bold, tooltip="Bold").pack(side="left", padx=2)
        make_icon_button(format_icons_frame, "italic", self.toggle_italic, tooltip="Italic").pack(side="left", padx=2)
        make_icon_button(format_icons_frame, "underline", self.toggle_underline, tooltip="Underline").pack(side="left", padx=2)

        ttk.Label(title_frame, text="Tags:").pack(side="left", padx=(8, 0))
        self.tags_var = tk.StringVar()
        ttk.Entry(title_frame, textvariable=self.tags_var, width=30).pack(side="left", padx=(6, 0))
        ttk.Button(title_frame, text="Add Tag", command=self._add_tag_from_entry).pack(side="left", padx=4)
        self._tags_label = ttk.Label(title_frame, text="")
        self._tags_label.pack(side="left", padx=(8, 0))

        # Toolbar area intentionally left empty (buttons removed)
        toolbar2 = ttk.Frame(center)
        toolbar2.pack(fill="x", padx=8, pady=(6, 0))
        # No visible toolbar buttons per request. File menu provides actions.

        right_controls = ttk.Frame(toolbar2)
        right_controls.pack(side="right")

        self.font_family_var = tk.StringVar(value=self.settings.get("font_family", FONT_FAMILIES[0]))
        font_family_cb = ttk.Combobox(right_controls, textvariable=self.font_family_var, values=FONT_FAMILIES, width=20, state="readonly")
        font_family_cb.pack(side="right", padx=(6, 0))
        font_family_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_font_settings())

        self.font_size_var = tk.IntVar(value=self.settings.get("font_size", FONT_SIZES[2]))
        font_size_cb = ttk.Combobox(right_controls, textvariable=self.font_size_var, values=FONT_SIZES, width=4, state="readonly")
        font_size_cb.pack(side="right", padx=(6, 0))
        font_size_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_font_settings())

        ttk.Label(right_controls, text="Size:").pack(side="right", padx=(0, 2))
        ttk.Label(right_controls, text="Font:").pack(side="right", padx=(0, 6))

        editor_frame = ttk.Frame(center)
        editor_frame.pack(fill="both", expand=True, padx=8, pady=6)
        self.text = tk.Text(editor_frame, wrap="word", undo=True)
        self.text.pack(fill="both", expand=True, side="left")
        self.text.bind("<<Modified>>", self._on_text_modified)
        self.text.bind("<KeyRelease>", self._on_key_release)
        base_font = tkfont.Font(self.text, self.text.cget("font"))
        base_font.configure(family=self.settings.get("font_family", "Segoe UI"), size=self.settings.get("font_size", 12))
        self.text.configure(font=base_font)

        try:
            bold_font = tkfont.Font(self.text, self.text.cget("font"))
            bold_font.configure(weight="bold")
            self.text.tag_configure("bold", font=bold_font)
        except Exception:
            self.text.tag_configure("bold", foreground="#000000")
        try:
            italic_font = tkfont.Font(self.text, self.text.cget("font"))
            italic_font.configure(slant="italic")
            self.text.tag_configure("italic", font=italic_font)
        except Exception:
            self.text.tag_configure("italic", foreground="#000000")
        try:
            underline_font = tkfont.Font(self.text, self.text.cget("font"))
            underline_font.configure(underline=1)
            self.text.tag_configure("underline", font=underline_font)
        except Exception:
            self.text.tag_configure("underline", underline=1)

        right = ttk.Frame(main, width=380)
        right.pack(side="right", fill="both")
        right.pack_propagate(False)
        ttk.Label(right, text="Live Preview", font=(self.settings.get("font_family", "Segoe UI"), 10, "bold")).pack(anchor="nw", padx=8, pady=(8, 0))
        self.preview = tk.Text(right, wrap="word", state="disabled")
        self.preview.pack(fill="both", expand=True, padx=8, pady=6)

        self.apply_theme()
        self._render_tag_chips()

    # Theme and font application
    def apply_persisted_settings(self):
        theme = self.settings.get("theme", DEFAULT_SETTINGS["theme"])
        self._set_theme(theme)
        self._apply_font_settings()

    def _apply_font_settings(self):
        fam = self.font_family_var.get() if hasattr(self, "font_family_var") else self.settings.get("font_family")
        size = int(self.font_size_var.get()) if hasattr(self, "font_size_var") else self.settings.get("font_size")
        self.settings["font_family"] = fam
        self.settings["font_size"] = size
        try:
            base_font = tkfont.Font(self.text, self.text.cget("font"))
            base_font.configure(family=fam, size=size)
            self.text.configure(font=base_font)
            pv_font = tkfont.Font(self.preview, self.preview.cget("font"))
            pv_font.configure(family=fam, size=max(10, size - 1))
            self.preview.configure(font=pv_font)
        except Exception:
            logger.exception("Failed to apply font settings")
        save_settings(self.settings)

    def _set_theme(self, theme_name: str):
        self.settings["theme"] = theme_name
        mapping = {
            "Minimal White": {"bg": "#ffffff", "fg": "#000000"},
            "Sepia": {"bg": "#f4ecd8", "fg": "#3b2f2f"},
            "Dark": {"bg": "#1e1e1e", "fg": "#dcdcdc"},
            "Solarized Light": {"bg": "#fdf6e3", "fg": "#657b83"},
            "Solarized Dark": {"bg": "#002b36", "fg": "#839496"},
            "Monokai": {"bg": "#272822", "fg": "#f8f8f2"},
            "Nord": {"bg": "#2e3440", "fg": "#d8dee9"},
            "Gruvbox": {"bg": "#fbf1c7", "fg": "#3c3836"},
            "High Contrast": {"bg": "#000000", "fg": "#ffffff"},
            "Soft Pastel": {"bg": "#fff7fb", "fg": "#5b4b66"},
        }
        colors = mapping.get(theme_name, mapping["Minimal White"])
        try:
            self.text.configure(bg=colors["bg"], fg=colors["fg"], insertbackground=colors["fg"])
            self.preview.configure(bg=colors["bg"], fg=colors["fg"])
        except Exception:
            logger.exception("Failed to apply theme")
        save_settings(self.settings)

    def toggle_theme(self):
        current = self.settings.get("theme", "Minimal White")
        idx = THEMES.index(current) if current in THEMES else 0
        next_theme = THEMES[(idx + 1) % len(THEMES)]
        self._set_theme(next_theme)

    def apply_theme(self):
        self._set_theme(self.settings.get("theme", DEFAULT_SETTINGS["theme"]))

    # Attachment gallery 
    def open_attachment_gallery(self):
        win = tk.Toplevel(self)
        win.title("Attachment Gallery")
        win.geometry("640x320")
        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        def make_thumb(att):
            path = att.get("path")
            fname = att.get("filename", "file")
            if path and os.path.exists(path) and PIL_AVAILABLE:
                try:
                    img = Image.open(path)
                    img.thumbnail((120, 120))
                    return (att, ImageTk.PhotoImage(img))
                except Exception:
                    return (att, None)
            return (att, None)

        thumbs = []

        def bg():
            for att in self._current_attachments:
                thumbs.append(make_thumb(att))
            return thumbs

        def on_done(result):
            for att, thumb in result:
                path = att.get("path")
                fname = att.get("filename", "file")
                if thumb:
                    container = ttk.Frame(frame)
                    btn = ttk.Button(container, image=thumb, command=lambda p=path: self.open_file(p))
                    btn.image = thumb
                    btn.pack()
                    lbl = ttk.Label(container, text=fname, wraplength=120)
                    lbl.pack()
                    container.pack(side="left", padx=6, pady=6)
                else:
                    ttk.Button(frame, text=fname, command=lambda p=path: self.open_file(p)).pack(side="left", padx=6, pady=6)

        run_in_background(bg, on_done)

    def open_file(self, path):
        try:
            if sys.platform.startswith("darwin"):
                os.system(f'open "{path}"')
            elif os.name == "nt":
                os.startfile(path)
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            messagebox.showinfo("Open file", f"Cannot open file: {path}")

    # Notes operations 
    def load_notes(self):
        self.status_var.set("Loading notes...")

        def bg():
            s = SessionLocal()
            try:
                q = self.search_var.get().strip()
                stmt = select(NoteModel).order_by(NoteModel.updated_at.desc().nullslast())
                res = s.execute(stmt).scalars().all()
                out = []
                for n in res:
                    try:
                        note_tags = json.loads(n.tags) if n.tags else []
                    except Exception:
                        note_tags = []
                    try:
                        attachments = json.loads(n.attachments) if n.attachments else []
                    except Exception:
                        attachments = []
                    try:
                        spans = json.loads(n.spans) if n.spans else []
                    except Exception:
                        spans = []
                    if q:
                        if q.lower() not in (n.title or "").lower() and q.lower() not in (n.body or "").lower() and q.lower() not in (n.ocr_text or "").lower():
                            continue
                    out.append({
                        "id": n.id,
                        "title": n.title,
                        "body": n.body,
                        "tags": note_tags,
                        "attachments": attachments,
                        "spans": spans,
                        "ocr_text": n.ocr_text or "",
                        "created_at": n.created_at.isoformat() if n.created_at else None,
                        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
                        "version": n.version,
                    })
                return out
            finally:
                s.close()

        def on_done(result):
            if isinstance(result, Exception):
                logger.exception("Failed to load notes (background)")
                self.status_var.set("Failed to load notes")
                return
            self._all_notes = result
            self.refresh_listbox()
            self.status_var.set("Notes loaded")

        run_in_background(bg, on_done)

    def _on_search_change(self):
        if hasattr(self, "_search_job") and self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(250, self.load_notes)

    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for n in self._all_notes:
            title = n.get("title") or "(untitled)"
            tags = ", ".join(n.get("tags") or [])
            self.listbox.insert(tk.END, f"{title}  [{tags}]")

    def new_note(self):
        self._current_note_id = None
        self._current_version = None
        self._current_attachments = []
        self._tag_list = []
        self.title_var.set("Untitled")
        self.text.delete("1.0", "end")
        self._render_tag_chips()
        self.render_preview()

    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        note = self._all_notes[idx]
        nid = note.get("id")
        self.load_note_by_id(nid)

    def load_note_by_id(self, nid):
        def bg():
            s = SessionLocal()
            try:
                note = s.get(NoteModel, nid)
                if not note:
                    raise RuntimeError("Note not found")
                try:
                    attachments = json.loads(note.attachments) if note.attachments else []
                except Exception:
                    attachments = []
                try:
                    spans = json.loads(note.spans) if note.spans else []
                except Exception:
                    spans = []
                try:
                    tags = json.loads(note.tags) if note.tags else []
                except Exception:
                    tags = []
                return {
                    "id": note.id,
                    "title": note.title,
                    "body": note.body,
                    "tags": tags,
                    "attachments": attachments,
                    "spans": spans,
                    "ocr_text": note.ocr_text or "",
                    "created_at": note.created_at.isoformat() if note.created_at else None,
                    "updated_at": note.updated_at.isoformat() if note.updated_at else None,
                    "version": note.version,
                }
            finally:
                s.close()

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Load failed", "Failed to load note.")
                return
            full = result
            self._current_note_id = full.get("id")
            self._current_version = full.get("version")
            self.title_var.set(full.get("title", ""))
            self.text.delete("1.0", "end")
            self.text.insert("1.0", full.get("body", "") or "")
            self._current_attachments = full.get("attachments", []) or []
            self._tag_list = full.get("tags", []) or []
            self._render_tag_chips()
            self.render_preview()

        run_in_background(bg, on_done)

    def save_note(self):
        content = self.text.get("1.0", "end-1c")
        spans = collect_spans_from_widget(self.text)
        payload_tags = self._tag_list
        attachments = self._current_attachments

        def bg():
            s = SessionLocal()
            try:
                now = datetime.utcnow()
                if self._current_note_id:
                    note = s.get(NoteModel, self._current_note_id)
                    if not note:
                        raise RuntimeError("Note not found")
                    note.title = self.title_var.get() or "Untitled"
                    note.body = content
                    note.tags = json.dumps(payload_tags)
                    note.attachments = json.dumps(attachments)
                    note.spans = json.dumps(spans)
                    note.updated_at = now
                    note.version = (note.version or 1) + 1
                    note.dirty = False
                    s.commit()
                    fts_upsert_note_row_by_id(note.id)
                    return {"id": note.id, "version": note.version}
                else:
                    import uuid
                    note = NoteModel(
                        id=str(uuid.uuid4()),
                        title=self.title_var.get() or "Untitled",
                        body=content,
                        tags=json.dumps(payload_tags) if payload_tags else "[]",
                        attachments=json.dumps(attachments) if attachments else "[]",
                        spans=json.dumps(spans) if spans else "[]",
                        ocr_text="",
                        created_at=now,
                        updated_at=now,
                        version=1,
                        dirty=False,
                    )
                    s.add(note)
                    s.commit()
                    s.refresh(note)
                    fts_upsert_note_row_by_id(note.id)
                    return {"id": note.id, "version": note.version}
            finally:
                s.close()

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Save failed", str(result))
                return
            self._current_note_id = result.get("id", self._current_note_id)
            self._current_version = result.get("version", self._current_version)
            self.load_notes()
            self.status_var.set("Saved")

        run_in_background(bg, on_done)

    def save_as(self):
        # Save As: prompt for filename and write PDF export of current note
        content = self.text.get("1.0", "end-1c")
        title = self.title_var.get() or f"{APP_NAME} Export"
        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], initialfile=sanitize_filename(title) + ".pdf")
        if not save_path:
            return
        def bg():
            pdf_bytes = json_to_pdf_bytes_with_assets({"title": title, "rows": [{"content": content}], "attachments": self._current_attachments}, include_assets=True)
            fd, tmp = tempfile.mkstemp(suffix=".pdf", dir=os.path.dirname(save_path) or ".")
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(pdf_bytes)
                f.flush()
                os.fsync(f.fileno())
            return tmp
        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Save As failed", str(result))
                logger.exception("Save As failed")
                return
            tmp = result
            final_pdf_path = save_path if save_path.lower().endswith(".pdf") else save_path + ".pdf"
            try:
                shutil.move(tmp, final_pdf_path)
                messagebox.showinfo("Save As", f"Saved PDF to:\n{final_pdf_path}")
            except Exception as e:
                messagebox.showerror("Save As failed", str(e))
                logger.exception("Failed to move saved PDF")
        run_in_background(bg, on_done)

    def delete_current_note(self):
        if not self._current_note_id:
            messagebox.showinfo("Delete", "No note selected to delete.")
            return
        if not messagebox.askyesno("Delete", "Delete this note permanently?"):
            return

        def bg():
            s = SessionLocal()
            try:
                note = s.get(NoteModel, self._current_note_id)
                if not note:
                    raise RuntimeError("Note not found")
                try:
                    attachments = json.loads(note.attachments) if note.attachments else []
                    for att in attachments:
                        if isinstance(att, dict) and att.get("path"):
                            try:
                                os.remove(att["path"])
                            except Exception:
                                pass
                except Exception:
                    pass
                s.delete(note)
                s.commit()
                fts_delete_row_by_id(self._current_note_id)
                return True
            finally:
                s.close()

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Delete failed", str(result))
                return
            messagebox.showinfo("Deleted", "Note deleted")
            self.new_note()
            self.load_notes()

        run_in_background(bg, on_done)

    # Open (file dialog)
    def open_file_dialog(self):
        # Allow opening PDFs or encrypted files. If PDF, open externally. If encrypted, attempt decrypt.
        file_path = filedialog.askopenfilename(title="Open file", filetypes=[("PDF files", "*.pdf"), ("Encrypted files", "*.pdf.enc;*.enc;*_encrypted.pdf"), ("All files", "*.*")])
        if not file_path:
            return
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".pdf":
            self.open_file(file_path)
            return
        # treat as encrypted blob
        if not CRYPTO_AVAILABLE:
            messagebox.showerror("Decryption unavailable", "Decryption requires the 'cryptography' package.")
            return
        # If user has stored password and enabled use, use it; otherwise prompt
        pwd = None
        if self.settings.get("use_stored_password") and self.settings.get("encryption_password"):
            pwd = self.settings.get("encryption_password")
        else:
            pwd = simpledialog.askstring("Decryption password", "Enter password to decrypt the file:", show="*")
            if pwd is None:
                return
        def bg():
            try:
                with open(file_path, "rb") as f:
                    blob = f.read()
                plain = decrypt_bytes_with_password(blob, pwd)
                fd, tmp = tempfile.mkstemp(suffix=".pdf", dir=EXPORTS_DIR)
                os.close(fd)
                with open(tmp, "wb") as out:
                    out.write(plain)
                    out.flush()
                    os.fsync(out.fileno())
                final = os.path.join(EXPORTS_DIR, sanitize_filename(os.path.splitext(os.path.basename(file_path))[0]) + "_decrypted.pdf")
                try:
                    shutil.move(tmp, final)
                except Exception:
                    try:
                        os.replace(tmp, final)
                    except Exception:
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        raise
                return final
            except Exception as e:
                logger.exception("Failed to open/decrypt %s", file_path)
                return e
        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Open failed", "Failed to open or decrypt file. See log.")
                return
            self.open_file(result)
            self.load_notes()
        run_in_background(bg, on_done)

    # Text formatting 
    def toggle_bold(self):
        try:
            sel = self.text.tag_ranges("sel")
            if not sel:
                return
            start, end = sel[0], sel[1]
            if "bold" in self.text.tag_names("sel.first"):
                self.text.tag_remove("bold", start, end)
            else:
                self.text.tag_add("bold", start, end)
        except Exception:
            pass

    def toggle_italic(self):
        try:
            sel = self.text.tag_ranges("sel")
            if not sel:
                return
            start, end = sel[0], sel[1]
            if "italic" in self.text.tag_names("sel.first"):
                self.text.tag_remove("italic", start, end)
            else:
                self.text.tag_add("italic", start, end)
        except Exception:
            pass

    def toggle_underline(self):
        try:
            sel = self.text.tag_ranges("sel")
            if not sel:
                return
            start, end = sel[0], sel[1]
            if "underline" in self.text.tag_names("sel.first"):
                self.text.tag_remove("underline", start, end)
            else:
                self.text.tag_add("underline", start, end)
        except Exception:
            pass

    # Preview 
    def _on_key_release(self, event=None):
        if hasattr(self, "_markdown_job") and self._markdown_job:
            self.after_cancel(self._markdown_job)
        self._markdown_job = self.after(400, self.render_preview)

    def render_preview(self):
        content = self.text.get("1.0", "end-1c")
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", content)
        self.preview.configure(state="disabled")

    # Export 
    def export_pdf(self):
        content = self.text.get("1.0", "end-1c")
        payload = {
            "title": self.title_var.get() or f"{APP_NAME} Export",
            "rows": [{"content": content}],
            "attachments": self._current_attachments,
        }
        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not save_path:
            return

        def bg():
            pdf_bytes = json_to_pdf_bytes_with_assets(payload, include_assets=True)
            fd, tmp = tempfile.mkstemp(suffix=".pdf", dir=os.path.dirname(save_path) or ".")
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(pdf_bytes)
                f.flush()
                os.fsync(f.fileno())
            return tmp

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Export failed", str(result))
                logger.exception("Export failed")
                return
            tmp = result
            final_pdf_path = save_path if save_path.lower().endswith(".pdf") else save_path + ".pdf"
            try:
                shutil.move(tmp, final_pdf_path)
                messagebox.showinfo("Export", f"Saved PDF to:\n{final_pdf_path}")
            except Exception as e:
                messagebox.showerror("Export failed", str(e))
                logger.exception("Failed to move exported PDF")

        run_in_background(bg, on_done)

    # Encrypt current note (uses stored password if enabled) 
    def encrypt_current_note(self):
        if not CRYPTO_AVAILABLE:
            messagebox.showerror("Encryption unavailable", "Encryption requires the 'cryptography' package. Install it and restart the app.")
            return
        # Determine password: stored or prompt
        pwd = None
        if self.settings.get("use_stored_password") and self.settings.get("encryption_password"):
            pwd = self.settings.get("encryption_password")
        else:
            pwd = simpledialog.askstring("Encryption password", "Enter a password to encrypt the exported PDF:", show="*")
            if not pwd:
                messagebox.showinfo("Encryption cancelled", "No password provided; encryption cancelled.")
                return

        content = self.text.get("1.0", "end-1c")
        payload = {
            "title": self.title_var.get() or f"{APP_NAME} Export",
            "rows": [{"content": content}],
            "attachments": self._current_attachments,
        }
        save_path = filedialog.asksaveasfilename(defaultextension=".pdf.enc", filetypes=[("Encrypted PDF", "*.pdf.enc")])
        if not save_path:
            return

        def bg():
            pdf_bytes = json_to_pdf_bytes_with_assets(payload, include_assets=True)
            enc = encrypt_bytes_with_password(pdf_bytes, pwd)
            fd, tmp = tempfile.mkstemp(suffix=".enc", dir=os.path.dirname(save_path) or ".")
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(enc)
                f.flush()
                os.fsync(f.fileno())
            return tmp

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Encryption failed", str(result))
                logger.exception("Encryption failed")
                return
            tmp = result
            try:
                shutil.move(tmp, save_path)
                messagebox.showinfo("Encrypted export", f"Saved encrypted PDF to:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Encryption failed", str(e))
                logger.exception("Failed to move encrypted file")

        run_in_background(bg, on_done)

    # Decrypt and open (uses stored password if enabled) 
    def decrypt_and_open(self):
        if not CRYPTO_AVAILABLE:
            messagebox.showerror("Decryption unavailable", "Decryption requires the 'cryptography' package. Install it and restart the app.")
            return
        file_path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Encrypted files", "*.pdf.enc;*_encrypted.pdf;*.enc;*")],
        )
        if not file_path:
            return
        pwd = None
        if self.settings.get("use_stored_password") and self.settings.get("encryption_password"):
            pwd = self.settings.get("encryption_password")
        else:
            pwd = simpledialog.askstring("Decryption password", "Enter the password to decrypt the file:", show="*")
            if pwd is None:
                messagebox.showinfo("Decryption cancelled", "No password provided; decryption cancelled.")
                return

        def bg():
            try:
                with open(file_path, "rb") as f:
                    blob = f.read()
                plain = decrypt_bytes_with_password(blob, pwd)
                base_name = sanitize_filename(os.path.splitext(os.path.basename(file_path))[0])
                fd, tmp = tempfile.mkstemp(suffix=".pdf", dir=EXPORTS_DIR)
                os.close(fd)
                with open(tmp, "wb") as out:
                    out.write(plain)
                    out.flush()
                    os.fsync(out.fileno())
                final = os.path.join(EXPORTS_DIR, f"{base_name}_decrypted.pdf")
                try:
                    shutil.move(tmp, final)
                except Exception:
                    try:
                        os.replace(tmp, final)
                    except Exception:
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        raise
                return final
            except Exception as e:
                logger.exception("Decryption failed for %s", file_path)
                return e

        def on_done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Decryption failed", "Failed to decrypt file. Check password and file integrity. See log for details.")
                return
            decrypted_path = result
            try:
                if sys.platform.startswith("darwin"):
                    os.system(f'open "{decrypted_path}"')
                elif os.name == "nt":
                    os.startfile(decrypted_path)
                else:
                    os.system(f'xdg-open "{decrypted_path}"')
            except Exception:
                messagebox.showinfo("Open file", f"Decrypted file saved to:\n{decrypted_path}\nCannot open automatically on this platform.")
            self.load_notes()

        run_in_background(bg, on_done)

    # Autosave 
    def _on_text_modified(self, event=None):
        try:
            if self.text.edit_modified():
                self.text.edit_modified(False)
                if hasattr(self, "_autosave_job") and self._autosave_job:
                    self.after_cancel(self._autosave_job)
                interval = int(self.settings.get("autosave_interval_s", DEFAULT_SETTINGS["autosave_interval_s"]))
                self._autosave_job = self.after(interval * 1000, self._autosave_now)
        except Exception:
            pass

    def _autosave_now(self):
        try:
            if self._current_note_id:
                self.save_note()
        except Exception:
            logger.debug("Autosave failed (silent)")

    # Tags 
    def _add_tag_from_entry(self):
        t = self.tags_var.get().strip()
        if not t:
            return
        if t not in self._tag_list:
            self._tag_list.append(t)
        self.tags_var.set("")
        self._render_tag_chips()

    def _render_tag_chips(self):
        tags_text = ", ".join(self._tag_list)
        self._tags_label.config(text=tags_text)


# Diagnostics and main 
def diagnose_environment() -> str:
    import platform, socket
    parts = []
    parts.append(f"Python {platform.python_version()} on {platform.system()} {platform.release()}")
    try:
        import tkinter
        parts.append("tkinter: OK")
    except Exception as e:
        parts.append(f"tkinter: MISSING ({e})")
    try:
        from PIL import Image
        parts.append("Pillow: OK")
    except Exception as e:
        parts.append(f"Pillow: MISSING ({e})")
    try:
        import requests
        parts.append("requests: OK")
    except Exception as e:
        parts.append(f"requests: MISSING ({e})")
    try:
        s = socket.socket()
        s.settimeout(0.2)
        s.connect(("127.0.0.1", 8000))
        s.close()
        parts.append("backend port 8000: reachable")
    except Exception:
        parts.append("backend port 8000: not reachable")
    if TESSERACT_AVAILABLE:
        parts.append("Tesseract: available")
    else:
        parts.append("Tesseract: not available")
    if CRYPTO_AVAILABLE:
        parts.append("cryptography: available")
    else:
        parts.append("cryptography: not available")
    return "\n".join(parts)


def main():
    init_db()
    logger.info("Embedded backend disabled in GUI. Start backend separately with: uvicorn maxnote:app --host 127.0.0.1 --port 8000")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as lf:
            lf.write("\n--- STARTUP DIAG ---\n")
            lf.write(diagnose_environment() + "\n")
    except Exception:
        logger.exception("Failed to write startup diag")
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        logger.error("No DISPLAY set; tkinter will fail in headless environment.")
        print("No DISPLAY environment variable set. Run with an X server or use X forwarding (ssh -X) or Xvfb.", file=sys.stderr)
        return
    try:
        global app_ui
        app_ui = MaxNoteUI()
        app_ui.mainloop()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logger.error("Frontend failed to start:\n%s", tb)
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Frontend error", f"Frontend failed to start. See log: {LOG_PATH}\n\n{str(e)}")
            root.destroy()
        except Exception:
            print("Frontend failed. See log:", LOG_PATH, file=sys.stderr)


if __name__ == "__main__":
    main()
