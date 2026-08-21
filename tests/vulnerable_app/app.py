import os
password = os.getenv("APP_PASSWORD")


def run(user_input):
    eval(user_input)
