username = request.form.get("user")
sql = "SELECT id FROM accounts WHERE login = '%s'" % username
db.execute(sql)
