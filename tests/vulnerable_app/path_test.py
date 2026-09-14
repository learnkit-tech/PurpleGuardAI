def read_user_file(request):
    filename = request.args.get("file")
    with open(filename) as f:
        return f.read()
