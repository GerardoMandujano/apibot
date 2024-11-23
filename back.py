from flask import Flask, request, jsonify
import sqlite3
import jwt
import bcrypt
from datetime import datetime, timedelta


app = Flask(__name__)
SECRET_KEY = "claveprueba"

DB = 'usuarios.db'

# Inicializar la base de datos
def inicializar_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        licencia TEXT NOT NULL UNIQUE,
                        expiracion DATE NOT NULL
                    )''')
    conn.commit()
    conn.close()
@app.route("/")
def root():
    return "Api iniciada correctamente"

@app.route('/registrar', methods=['POST'])
def registrar_usuario():
    data = request.json
    email = data['email']
    password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    licencia = data['licencia']
    expiracion = datetime.now() + timedelta(days=30)

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usuarios (email, password, licencia, expiracion) VALUES (?, ?, ?, ?)",
                       (email, password, licencia, expiracion))
        conn.commit()
        return jsonify({"mensaje": "Usuario registrado exitosamente"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"mensaje": "Email o licencia ya registrados"}), 400
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login_usuario():
    data = request.json

    # Validar que se reciban los campos 'email' y 'password'
    if 'email' not in data or 'password' not in data:
        return jsonify({"mensaje": "Faltan campos requeridos: email o password"}), 400

    email = data['email']
    password = data['password']

    try:
        # Usar un bloque 'with' para asegurar que la conexión se cierre automáticamente
        with sqlite3.connect(DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
            usuario = cursor.fetchone()

        # Verificar si el usuario existe y la contraseña es correcta
        if usuario:
            # La contraseña almacenada en la base de datos ya es un objeto 'bytes'
            # Solo necesitamos aplicar .encode() a la contraseña proporcionada
            if bcrypt.checkpw(password.encode('utf-8'), usuario[2]):
                token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY,
                                   algorithm="HS256")
                return jsonify({"token": token}), 200
            else:
                return jsonify({"mensaje": "Credenciales incorrectas"}), 403

        return jsonify({"mensaje": "Usuario no encontrado"}), 404

    except sqlite3.DatabaseError as e:
        return jsonify({"mensaje": f"Error en la base de datos: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"mensaje": f"Error inesperado: {str(e)}"}), 500


@app.route('/validar', methods=['POST'])
def validar_licencia():
    data = request.json

    # Validar que el campo 'token' esté presente
    if 'token' not in data:
        return jsonify({"mensaje": "Falta el campo 'token'"}), 400

    token = data['token']

    try:
        # Decodificar el token JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload['email']
    except jwt.ExpiredSignatureError:
        return jsonify({"mensaje": "Token expirado"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"mensaje": "Token inválido"}), 403
    except Exception as e:
        return jsonify({"mensaje": f"Error al decodificar el token: {str(e)}"}), 500

    try:
        # Usar 'with' para manejar automáticamente la conexión a la base de datos
        with sqlite3.connect(DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
            usuario = cursor.fetchone()

        # Verificar si se encontró el usuario
        if usuario:
            # Convertir la fecha de expiración desde la base de datos, incluyendo fracciones de segundo
            expiracion = datetime.strptime(usuario[4], '%Y-%m-%d %H:%M:%S.%f')
            if expiracion > datetime.now():
                return jsonify({"mensaje": "Licencia válida"}), 200
            else:
                return jsonify({"mensaje": "Licencia expirada"}), 403
        else:
            return jsonify({"mensaje": "Usuario no encontrado"}), 404

    except sqlite3.DatabaseError as e:
        return jsonify({"mensaje": f"Error en la base de datos: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"mensaje": f"Error inesperado: {str(e)}"}), 500

if __name__ == "__main__":
    inicializar_db()
    app.run(debug=True)
