def search(request):
    user_id = request.args.get("user_id")
    if not user_id.isdigit():
        return "bad input"
    query = "SELECT * FROM users WHERE id='" + user_id + "'"
    connection.execute(query)
