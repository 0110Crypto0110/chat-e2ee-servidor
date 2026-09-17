import socket
import threading
import sqlite3
from datetime import datetime

HOST = '127.0.0.1'
PORT = 5000

online_users = {}
online_users_lock = threading.Lock()
users_lock = threading.Lock()

def get_db_connection():
    conn = sqlite3.connect('chat_server.db')
    return conn

def get_all_users_with_status():
    """Busca todos os usuários do banco de dados e retorna com seus status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    with users_lock:
        cursor.execute("SELECT username FROM users")
        all_users = [row[0] for row in cursor.fetchall()]

    with online_users_lock:
        online_usernames = list(online_users.keys())

    contact_list = []
    for user in all_users:
        status = "online" if user in online_usernames else "offline"
        contact_list.append(f"{user}:{status}")

    conn.close()
    return contact_list

def send_contact_list_to_all():
    """Envia a lista de contatos atualizada para todos os usuários online."""
    contact_list = get_all_users_with_status()
    message_to_send = f"CONTACTS_LIST|{'|'.join(contact_list)}"
    
    with online_users_lock:
        for user_conn in online_users.values():
            try:
                user_conn.sendall(message_to_send.encode('utf-8'))
            except socket.error:
                pass

def deliver_offline_messages(username, conn):
    """
    Entrega mensagens que estavam armazenadas para o usuário.
    """
    conn_db = get_db_connection()
    cursor = conn_db.cursor()

    try:
        cursor.execute("SELECT sender, message, timestamp FROM offline_messages WHERE receiver=?", (username,))
        messages = cursor.fetchall()
        
        if messages:
            print(f"[OFFLINE MESSAGES] Entregando {len(messages)} mensagens para {username}.")
            for sender, message, timestamp in messages:
                conn.sendall(f"MESSAGE|{sender}|{message}|{timestamp}".encode('utf-8'))
            
            cursor.execute("DELETE FROM offline_messages WHERE receiver=?", (username,))
            conn_db.commit()

    except sqlite3.Error as e:
        print(f"Erro ao entregar mensagens offline: {e}")
    finally:
        if conn_db:
            conn_db.close()

def handle_client(conn, addr):
    print(f"[NOVA CONEXÃO] Cliente {addr} conectado.")
    current_username = None

    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break

            parts = data.split('|')
            command = parts[0]

            if command == "REGISTER" and len(parts) == 3:
                username, password = parts[1], parts[2]
                conn_db = get_db_connection()
                cursor = conn_db.cursor()
                try:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    conn_db.commit()
                    response = "REGISTRO_OK"
                except sqlite3.IntegrityError:
                    response = "REGISTRO_FALHA|Nome de usuário já existe."
                finally:
                    conn_db.close()
                conn.sendall(response.encode('utf-8'))

            elif command == "LOGIN" and len(parts) == 3:
                username, password = parts[1], parts[2]
                conn_db = get_db_connection()
                cursor = conn_db.cursor()
                try:
                    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                    user = cursor.fetchone()
                    if user:
                        with online_users_lock:
                            if username in online_users:
                                conn.sendall("LOGIN_FALHA|Usuário já está logado.".encode('utf-8'))
                                break
                            online_users[username] = conn
                        current_username = username
                        response = "LOGIN_OK"
                        conn.sendall(response.encode('utf-8'))
                        send_contact_list_to_all()
                        deliver_offline_messages(username, conn)
                    else:
                        response = "LOGIN_FALHA|Usuário ou senha inválidos."
                        conn.sendall(response.encode('utf-8'))
                finally:
                    conn_db.close()
            
            elif command == "GET_CONTACTS":
                send_contact_list_to_all()

            elif command == "LOGOUT":
                if current_username:
                    with online_users_lock:
                        if current_username in online_users:
                            del online_users[current_username]
                    send_contact_list_to_all()
                break

            elif command == "MESSAGE" and len(parts) >= 3:
                receiver = parts[1]
                message = '|'.join(parts[2:])
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                with online_users_lock:
                    if receiver in online_users:
                        recipient_conn = online_users[receiver]
                        recipient_conn.sendall(f"MESSAGE|{current_username}|{message}|{timestamp}".encode('utf-8'))
                    else:
                        conn_db = get_db_connection()
                        cursor = conn_db.cursor()
                        try:
                            cursor.execute("INSERT INTO offline_messages (sender, receiver, timestamp, message) VALUES (?, ?, ?, ?)", (current_username, receiver, timestamp, message))
                            conn_db.commit()
                            conn.sendall("INFO|Mensagem armazenada, será entregue quando o usuário ficar online.".encode('utf-8'))
                        except sqlite3.Error as e:
                            conn.sendall("ERRO|Falha ao armazenar mensagem.".encode('utf-8'))
                        finally:
                            if conn_db:
                                conn_db.close()

            elif command == "TYPING" and len(parts) == 2:
                receiver = parts[1]
                with online_users_lock:
                    if receiver in online_users:
                        recipient_conn = online_users[receiver]
                        recipient_conn.sendall(f"TYPING|{current_username}".encode('utf-8'))

            elif command == "TYPING_STOP" and len(parts) == 2:
                receiver = parts[1]
                with online_users_lock:
                    if receiver in online_users:
                        recipient_conn = online_users[receiver]
                        recipient_conn.sendall(f"TYPING_STOP|{current_username}".encode('utf-8'))
            
    except (socket.error, sqlite3.Error) as e:
        pass
    finally:
        with online_users_lock:
            if current_username in online_users:
                del online_users[current_username]
                send_contact_list_to_all()
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()