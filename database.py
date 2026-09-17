import sqlite3

def create_tables():
    """Cria as tabelas users e offline_messages no banco de dados."""
    try:
        conn = sqlite3.connect('chat_server.db')
        cursor = conn.cursor()

        # Tabela para armazenar usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Tabela para armazenar mensagens para usuários offline
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS offline_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL
            )
        ''')

        conn.commit()
        print("Tabelas criadas com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao criar tabelas: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()