import sys, re
which, state = sys.argv[1], sys.argv[2]
s = open('server.js', encoding='utf-8').read()
IDOR_FIX = """    const order = db
      .prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?')
      .get(Number(orderMatch[1]), me.id);"""
IDOR_VUL = """    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(orderMatch[1]));"""
SQLI_FIX = """      const rows = db
        .prepare('SELECT id, name, price FROM products WHERE name LIKE ?')
        .all('%' + q + '%');"""
SQLI_VUL = """      const rows = db.prepare("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'").all();"""
a, b = (IDOR_FIX, IDOR_VUL) if which == 'idor' else (SQLI_FIX, SQLI_VUL)
src, dst = (b, a) if state == 'fix' else (a, b)
if src in s:
    open('server.js','w',encoding='utf-8').write(s.replace(src, dst))
