from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from typing import Optional
from dotenv import load_dotenv
import jwt
import datetime
import os
import re

# ─── Cargar variables de entorno ────────────────────────────────────────────
load_dotenv()

SECRET_KEY   = os.getenv("SECRET_KEY")
ALGORITHM    = os.getenv("ALGORITHM", "HS256")
ADMIN_USER   = os.getenv("ADMIN_USER")
ADMIN_PASS   = os.getenv("ADMIN_PASS")
DOCENTE_PASS = os.getenv("DOCENTE_PASS")           # contraseña genérica mientras no haya BD
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")

# Validación temprana: si faltan vars críticas, el servidor no arranca
for var_name, var_val in [("SECRET_KEY", SECRET_KEY), ("ADMIN_USER", ADMIN_USER), ("ADMIN_PASS", ADMIN_PASS)]:
    if not var_val:
        raise RuntimeError(f"Variable de entorno requerida no encontrada: {var_name}")

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(title="Login Central UNACH", version="1.1.0")

# ─── CORS seguro ─────────────────────────────────────────────────────────────
# allow_credentials=True NO es compatible con allow_origins=["*"]
# Se deben especificar los orígenes exactos
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,      # lista desde .env
    allow_credentials=True,
    allow_methods=["GET", "POST"],      # solo los métodos necesarios
    allow_headers=["Authorization", "Content-Type"],
)

# ─── Seguridad Bearer ────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer()

# ─── Modelos ─────────────────────────────────────────────────────────────────
class AdminLogin(BaseModel):
    usuario: str
    password: str

    @field_validator("usuario", "password")
    @classmethod
    def no_vacio(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("El campo no puede estar vacío")
        return v.strip()


class DocenteLogin(BaseModel):
    rfc:      Optional[str] = None
    usuario:  Optional[str] = None
    password: Optional[str] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────
RFC_REGEX = re.compile(
    r"^[A-ZÑ&]{3,4}"   # 3 letras (moral) o 4 letras (física)
    r"\d{6}"            # fecha de nacimiento AAMMDD
    r"[A-Z0-9]{3}$",    # homoclave
    re.IGNORECASE,
)

def validar_rfc(rfc: str) -> bool:
    """Verifica formato de RFC mexicano (persona física y moral)."""
    return bool(RFC_REGEX.match(rfc.strip()))


def crear_token(datos: dict) -> str:
    """Genera un JWT firmado con expiración de 8 horas."""
    payload = datos.copy()
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    payload["iat"] = datetime.datetime.utcnow()
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """Dependencia reutilizable para rutas protegidas."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


# ─── Rutas públicas ───────────────────────────────────────────────────────────
@app.post("/api/login", summary="Login de administrador")
def login_admin(user: AdminLogin):
    # Comparación con credenciales desde .env (sin hardcodear)
    if user.usuario != ADMIN_USER or user.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Credenciales de administrador inválidas")

    token = crear_token({"sub": user.usuario, "rol": "admin"})
    return {"token": token, "rol": "admin"}


@app.post("/api/login-docente", summary="Login de docente por RFC o usuario/contraseña")
def login_docente(user: DocenteLogin):
    # Caso 1 ── RFC solo (sin contraseña)
    if user.rfc and not user.password:
        if not validar_rfc(user.rfc):
            raise HTTPException(
                status_code=422,
                detail="RFC inválido. Formato esperado: AAAA######XXX (persona física) o AAA######XXX (moral)",
            )
        # TODO: consultar BD para verificar que el RFC exista
        # docente = db.query(Docente).filter(Docente.rfc == user.rfc.upper()).first()
        # if not docente: raise HTTPException(404, "RFC no encontrado")
        token = crear_token({"sub": user.rfc.upper(), "rol": "docente"})
        return {"token": token, "rol": "docente"}

    # Caso 2 ── Usuario + contraseña
    if user.usuario and user.password:
        if user.password != DOCENTE_PASS:
            raise HTTPException(status_code=401, detail="Credenciales de docente inválidas")
        # TODO: consultar BD para verificar usuario
        token = crear_token({"sub": user.usuario, "rol": "docente"})
        return {"token": token, "rol": "docente"}

    raise HTTPException(
        status_code=400,
        detail="Envía RFC (solo), o usuario + contraseña",
    )


# ─── Ruta protegida de ejemplo ────────────────────────────────────────────────
@app.get("/api/me", summary="Datos del usuario autenticado")
def me(payload: dict = Depends(verificar_token)):
    """Ruta protegida: cualquier microservicio puede usarla para validar tokens."""
    return {"sub": payload.get("sub"), "rol": payload.get("rol")}


@app.get("/", summary="Health check")
def root():
    return {"status": "ok", "sistema": "UNACH Login Central v1.1"}