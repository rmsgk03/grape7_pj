import os
import sqlite3


conn = sqlite3.connect("app.db")
cursor = conn.cursor()

user_id = input("user id: ")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

filename = input("file name: ")
open(filename).read()

cmd = "ping " + user_id
os.system(cmd)
