from network import LoginServer, GameServer


# import time

# IP = "localhost"
# LS_PORT = 2106
# GS_PORT = 2112


class Bot:
    def __init__(self, ip="localhost", ls_port=2106, gs_port=2112):
        self.ip = ip
        self.ls_port = ls_port
        self.gs_port = gs_port

        self.ls = LoginServer()
        self.gs = GameServer()

    def connect(self, login, password):
        self.ls.connect(self.ip, self.ls_port)
        self.ls.login(login, password)

# usage examples:
# ctx = Bot.connect(IP, LS_PORT, GS_PORT)

# me = ctx.self

# target = ctx.npcs[0]

# me.move_to(target)
# me.move(544.134, 123.54, -5.33)
# me.attack(target)
# me.do_action(db.actions.find("high five"))
# me.useskill(db.skills.find("wind strike"))
# me.equip_item(db.items.find("leather helmet"))
# me.unequip_item(db.items.find("leather helmet"))

# me.target == target # True
# me.hp
# me.mp
# me.cp
# me.actions
# me.pvp
# me.pk
# me.exp


# ctx.self
# ctx.npcs
# ctx.pcs
# actions
# ctx.events.subscribe("hit", do_stuff)
# ctx.events.unsubscribe("hit", do_stuff)

# ctx.exit()

# ls = LoginServer()
# ls.connect(IP, LS_PORT)

# gs_session_id, gs_account_id, gs_id, ls_account_id, ls_auth_key = ls.login("test", "test")

# gs = GameServer()

# gs.connect(IP, GS_PORT)
# gs.start_loop(gs_session_id, gs_account_id, gs_id, ls_account_id, ls_auth_key)

# time.sleep(10)
