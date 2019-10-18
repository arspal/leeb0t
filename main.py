from network import LoginServer

IP = "localhost"
LS_PORT = 2106
GS_PORT = 7777

ls = LoginServer()
ls.connect(IP, LS_PORT)
ls.login("admin", "password")
