from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import jwt
import datetime

app = FastAPI(title="Login Central UNACH")

# Configuración de CORS para que tu React pueda hablar con este backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # En producción aquí iría la URL de tu Vercel
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# LA LLAVE MAESTRA COMPARTIDA CON XIMENA
SECRET_KEY = "SIAE_UNACH_SECRET_KEY_2026"
ALGORITHM = "HS256"

# Modelos de datos que espera recibir
class AdminLogin(BaseModel):
    usuario: str
    password: str

class DocenteLogin(BaseModel):
    rfc: str

# Función para generar el JWT
def crear_token(datos: dict):
    to_encode = datos.copy()
    to_encode.update({"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Endpoint 1: Login de Administrador
@app.post("/api/login")
def login_admin(user: AdminLogin):
    # Aquí en el futuro conectarías a tu base de datos MySQL/Postgres. Por ahora, validación directa:
    if user.usuario == "admin" and user.password == "unach2026":
        token = crear_token({"sub": user.usuario, "role": "admin"})
        return {"token": token}
    raise HTTPException(status_code=401, detail="Credenciales de administrador inválidas")

# Endpoint 2: Login de Docente
@app.post("/api/login-docente")
def login_docente(user: DocenteLogin):
    # Simulamos que cualquier RFC de 10 o más caracteres es válido
    if len(user.rfc) >= 10:
        token = crear_token({"sub": user.rfc, "role": "docente"})
        return {"token": token}
    raise HTTPException(status_code=401, detail="RFC no encontrado en el sistema")