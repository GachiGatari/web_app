import os


import dotenv
dotenv.read_dotenv()

print(os.environ.get("CLIENT_ID"))