from network import Connection, LoginConn, GameConn
import packets

# import time

move_packet = packets.gs_move_to_loc
move_packet["fields"] = {'op_code': 0x0F, 'dest_x': 149411, 'dest_y': 46842, 'dest_z': -3408, 'curr_x': 0,
                         'curr_y': 0, 'curr_z': 0, 'controller': 1}

ls = LoginConn()

ls.connect("localhost", 2106)
g = ls.login("test", "test")

gs = GameConn()

gs.connect("localhost", 2112)
gs.start_loop(g[0], g[1], g[2], ls.account_id, ls.auth_key)
ls.sock.close()

# time.sleep(15)

"""
usage examples:
bot = Bot()
ctx = bot.connect()

ctx.conn.status

me = ctx.self

target = ctx.npcs[0]с 

me.move_to(target)
me.move(544.134, 123.54, -5.33)
me.attack(target)
me.do(db.actions.find("high five"))
me.use(db.skills.find("wind strike"))
me.equip(db.items.find("leather helmet"))
me.unequip(db.items.find("leather helmet"))

me.target == target # True
me.hp
me.mp
me.cp
me.actions
me.pvp
me.pk
me.exp

ctx.self
ctx.npcs
ctx.pcs
actions
ctx.events.subscribe("hit", do_stuff)
ctx.events.unsubscribe("hit", do_stuff)

ctx.exit()

"""


class Bot:
    def __init__(self, ip="localhost", ls_port=2106, gs_port=2112):
        self.conn = Connection(ip, ls_port, gs_port)

    def connect(self, login, password):
        self.conn.connect(login, password)
