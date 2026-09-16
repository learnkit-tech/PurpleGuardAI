def search(request):
    username = request.args.get("username")
    query = "SELECT * FROM users WHERE name='" + username + "'"
    connection.execute(query)
