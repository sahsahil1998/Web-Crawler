from html.parser import HTMLParser
from collections import deque


class MyHTMLParser(HTMLParser):

    pagesToVisit = deque() # holds a list of all URLs that still need to be read
    pagesVisited = set() # holds all the unique pages visited
    secretFlags = set() # holds the 5 secret flags found

    def __init__(self):
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    url = attr[1]
                    if '/fakebook/' in url and url not in self.pagesToVisit:
                            self.pagesToVisit.append(url)
                            #print(f"adding the following url: {url}")
                        
    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        if 'FLAG:' in data:
            flag = data.split(':')[1].strip()
            # add flag into the set
            self.secretFlags.add(flag)
            print(flag)

