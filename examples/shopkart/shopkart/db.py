"""Database helpers (sqlite3)."""
import sqlite3


def init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total REAL);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO users (name) VALUES ('asha'), ('ravi');
        INSERT INTO orders (customer_id, total) VALUES (1, 250.0), (1, 99.5), (2, 10.0);
        INSERT INTO products (name) VALUES ('pen'), ('pencil'), ('notebook');
        """
    )


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT id, name FROM users WHERE name = '{username}'")
    return cur.fetchone()


def count_rows(conn, table="orders"):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def find_orders(conn, customer_id):
    query = "SELECT id, total FROM orders WHERE customer_id = " + str(customer_id)
    return conn.execute(query).fetchall()


def search_products(conn, term):
    return conn.execute(_like_query(term)).fetchall()


def _like_query(term):
    return f"SELECT name FROM products WHERE name LIKE '%{term}%'"
