import bs4 as bs
import urllib.request

code =  'cve-2014-0114'

source = urllib.request.urlopen('https://nvd.nist.gov/vuln/detail/' + code).read()

soup = bs.BeautifulSoup(source, 'lxml')

table_row = soup.find_all("td", attrs={'data-testid': "vuln-CWEs-link-0"})

code = table_row[0]
print(code.text.strip())
