import re

def search(request):
    username = request.args.get("username")
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return "bad input"
    query = "SELECT * FROM users WHERE name='" + username + "'"
    connection.execute(query)
