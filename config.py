import psycopg2

def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="empresa_db",
        user="postgres",
        password="sccp1910"
    )