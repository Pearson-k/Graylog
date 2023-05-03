import yaml
import glob
from pathlib import Path
from datetime import datetime, timedelta
import json
import socket
import git
import os
import shutil

# Graylog stuff, must have a running GELF UDP input
graylog_ip = '127.0.0.1'
graylog_port = 2514


#How many days you want to pull articles for.
days_to_lookback = 30


#Which RSS feeds you want to ingest into Graylog.
feeds = [
   'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
   'https://securelist.com/feed/',
   'http://feeds.feedburner.com/NakedSecurity',
   'https://www.microsoft.com/security/blog/feed/',
   'https://www.malwarebytes.com/blog/feed/index.xml',
   'https://feeds.feedburner.com/TroyHunt',
   'https://blog.knowbe4.com/rss.xml',
   'https://blog.talosintelligence.com/feeds/posts/default/-/threats',
   'https://krebsonsecurity.com/feed/',
   'https://www.theregister.com/security/headlines.atom',
   'https://www.darkreading.com/rss.xml'
]


#datetime stuff for deltas
now = datetime.now()
start_date = now - timedelta(days = days_to_lookback)   

def parseCVEs(): 
    import requests

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    params = dict(
        lastModStartDate=(datetime.now() - timedelta(days = 1)).isoformat(),
        lastModEndDate=datetime.now().isoformat(),
        #cvssV3Severity='CRITICAL'
    )

    resp = requests.get(url=url, params=params)
    data = resp.json()

    for item in data['vulnerabilities']:
        d={}
        d['CVE_ID']=item['cve']['id']
        d['CVE_Description']=item['cve']['descriptions'][0]['value']
        d['CVE_Metrics']=item['cve']['metrics']
        if item['cve']['references']:
            d['Reference']=item['cve']['references'][0]['url']
        d.update( [('version', '1.1'),('host','NewsFeed'),('short_message','A Critical CVE Was Updated: ' + item['cve']['id'])])
        msg = json.dumps(d)
        sendEvent(msg)

def parseFeed(URL):
    import feedparser

    feed = feedparser.parse(URL)

    feed_entries = feed.entries
    d={}
    for entry in feed.entries:
        article_title = entry.title
        article_link = entry.link
        article_date = datetime(*(entry.published_parsed[0:6]))
        if article_date > start_date:
            d.update( [('version', '1.1'),('host','NewsFeed'),('short_message','New News Article: ' + article_title),('News_Article_Title',article_title),('Article_Link',article_link),('Article_Publish_date',str(article_date.isoformat()))] )
            msg = json.dumps(d)
            sendEvent(msg)

def parseSigma():
    files = glob.glob("sigma_rules/rules" + "/**/*.yml", recursive=True)
    destination = Path() / "sigma_rules"
    if not os.path.exists(destination):
        git.Repo.clone_from('https://github.com/SigmaHQ/sigma.git', destination)
    else: 
        shutil.rmtree('sigma_rules')
        git.Repo.clone_from('https://github.com/SigmaHQ/sigma.git', destination)
    
    for file in files:
        d={}
        with open(file, 'r') as stream:
            docs = yaml.load_all(stream, Loader=yaml.FullLoader)
            for doc in docs:
                for k,v in doc.items():
                    if k in ['modified','title','description','tags','author','logsource']:
                        d[k]=v
                    elif k == 'level':
                        d['Sigma_Severity']=v
                    elif k == 'date':
                        date = datetime.strptime(v, "%Y/%m/%d")
                        d['date']=date.isoformat()
                    elif k =='references':
                        d['date']=k[0]
                d.update( [('version', '1.1'),('host','NewsFeed'),('short_message','New Sigma Rule Detected: ' + d['title']),('sigma_file', 'rules' + file.split('sigma_rules', 1)[1])])
                if date > start_date:
                    msg = json.dumps(d)
                    #print(msg)
                    sendEvent(msg)

def sendEvent(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((graylog_ip, graylog_port))
    encoded = msg.encode('utf-8')
    sock.send(encoded)

if __name__ == '__main__':
    parseSigma()
    for feed in feeds:
       parseFeed(feed)
    parseCVEs()