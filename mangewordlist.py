import os

wordlists = []
masterbook = open("masterList.txt", "w", encoding="utf8")

with open("masterList.txt", "w+b") as mb:
    for root, dirs, files in os.walk("wordlists"):
        for name in files:
            if name.endswith(".txt"):
                with open(os.path.join(root,name), "rb") as wd:
                    text = wd.read()
                    mb.write(text)

#print(wordlists)