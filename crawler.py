import requests


def request(url):
    try:
        return requests.get("http://" + url)

        print(get_response)
    except requests.exceptions.ConnectionError:
        pass


target_url = "192.168.98.146/"
with open("/root/PycharmProjects/Webcrawler/subdomains-wodlist.txt", "r") as wordlist_file:
    for line in wordlist_file:
        word = line.strip()
        test_url = target_url + "/" + word
        response = request(test_url)
        if response:
            print("[+] Discovered domain --> " + test_url)

