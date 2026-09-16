def search(request):
    username = request.args.get("username")
    if not username.isalnum():
        return "bad input"
    query = "SELECT * FROM users WHERE name='" + username + "'"
    connection.execute(query)
