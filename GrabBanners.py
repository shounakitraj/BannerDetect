# from Classes.grabber import GrabBanners
import httplib
import re
import ssl
import urllib2
import os
import sys
import csv
import requests
from BeautifulSoup import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # Disable unverified SSL certificate warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


ROutput = "ReconOutput.txt"
try:
    os.remove(ROutput)
    File = open(ROutput, "w+")
except Exception, e:
    File = open(ROutput, "w+")

# r = s.post(URL1, headers=loginheaders, data=Data, proxies=proxydict, verify=False)
'''HeaderList = ["Server", "Date", "Via", "X-Powered-By", "X-Country-Code", "Content-Length", "accept-ranges",
           'keep-alive']'''
HeaderList = ["Server", "Via", "X-Powered-By"]
Pattern = re.compile('apache|JSP Engine|jetty|php|ssl', re.IGNORECASE)
Methods = ['post', 'get', 'put', 'trace']
Headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'}

############# URLLIB2 #############################
# proxy = urllib2.ProxyHandler({'https': '127.0.0.1:8080'})
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
# opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
opener.addheaders = [('User-Agent',
                      'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'),
                     ('Accept-Encoding', 'gzip, deflat')]
httplib.HTTPSConnection._http_vsn = 10
############# URLLIB2 #############################

def ChangeMethod(Link):
    Status = StatusCode = ""
    try:
        if "http" not in Link:
            Link = "https://" + Link + "/"
        for Method in Methods:
            Request = getattr(requests, Method)
            Response = Request(Link, headers=Headers, allow_redirects=False, verify=False)
            Status = str(Response.status_code) + " " + Response.reason
            StatusCode = Response.status_code
            if StatusCode == 302:
                if '//' not in Response.headers['Location']:
                    RedirectLocation = '/'.join(Response.headers['Location'].rsplit('/')).strip('/')
                    RedirectLocation = Link + RedirectLocation + "/"
                elif '//' in Response.headers['Location']:
                    RedirectLocation = Response.headers['Location']
                if RedirectLocation not in Urls:
                    File.write("%s | Redirecting to %s\n" % (Link, RedirectLocation))
                    print ("%s | Redirecting to %s" % (Link, RedirectLocation))
                    Urls.append(RedirectLocation)

            PrintResponseHeaders(Link, Response, str(Method))

            # Response body
            Response = BeautifulSoup(Response.text)
            for elem in Response(text=Pattern):
                if "30" in str(StatusCode) or "200" in str(StatusCode):
                    File.write(Link + " | (" + Status + ")  Version | " + str(elem.parent) + "\n")
                    print (Link + " | (" + Status + ")  Version | " + str(elem.parent))
                else:
                    File.write(
                        Link + " | (" + Status + ")  Version | " + str(elem.parent) + " (Potential Vulnerable Location)\n")
                    print (Link + " | (" + Status + ")  Version | " + str(elem.parent) + " (Potential Vulnerable Location)")
    except Exception, e:
        File.write(Link + " | (" + Status + ")  | ChangeMethod | " + str(e) + "\n")
        print (Link + " | (" + Status + ")  | ChangeMethod | " + str(e))


def PageNotFound(Link):
    Status = StatusCode = ""
    try:
        if "http" not in Link:
            Link = "https://" + Link + "/xxxxxxxxxx/"
        Response = requests.get(Link, headers=Headers, allow_redirects=False, verify=False)
        Status = str(Response.status_code) + " " + Response.reason
        StatusCode = Response.status_code

        # Response body
        Response = BeautifulSoup(Response.text)
        for elem in Response(text=Pattern):
            if "30" in str(StatusCode) or "200" in str(StatusCode):
                File.write(Link + " (" + Status + ") | Version | " + str(elem.parent) + "\n")
                print (Link + " (" + Status + ") | Version | " + str(elem.parent))
            else:
                File.write(
                    Link + " (" + Status + ") | Version | " + str(elem.parent) + " (Potential Vulnerable Location)\n")
                print (Link + " (" + Status + ") | Version | " + str(elem.parent) + " (Potential Vulnerable Location)")
    except Exception, e:
        #
        File.write(Link + " (" + Status + ") | PageNotFound | " + str(e) + "\n")
        print (Link + " (" + Status + ") | PageNotFound | " + str(e))


def ChangeProtocol(Link):
    try:
        if "http" not in Link:
            Link = "https://" + Link + "/"
        # Use HTPT/1.0
        httplib.HTTPSConnection._http_vsn_str = 'HTPT/1.0'
        Response = opener.open(Link)

        # Response body
        Response = BeautifulSoup(Response.read())
        for elem in Response(text=Pattern):
            File.write(Link + " | Version | " + str(elem.parent) + "\n")
            print (Link + " | Version | " + str(elem.parent))
    except Exception, e:
        File.write(Link + " | ChangeProtocol (HTPT/1.0)| " + str(e) + "\n")
        print (Link + " | ChangeProtocol (HTPT/1.0)| " + str(e))
    try:
        # USe HTTP/3.0
        httplib.HTTPSConnection._http_vsn_str = 'HTTP/3.0'
        Response = opener.open(Link)

        # Response body
        Response = BeautifulSoup(Response.read())
        for elem in Response(text=Pattern):
            File.write(Link + " | Version | " + str(elem.parent) + "\n")
            print (Link + " | Version | " + str(elem.parent))
    except Exception, e:
        File.write(Link + " | ChangeProtocol (HTTP/3.0)| " + str(e) + "\n")
        print (Link + " | ChangeProtocol (HTTP/3.0)| " + str(e))

def AddHeaders(Link):
    try:
        Headers.update({'content-type': 'application', 'X-Forwarded-For': 'xxxxxx'})
        if "http" not in Link:
            Link = "https://" + Link + "/"
        Response = requests.get(Link, headers=Headers, allow_redirects=False, verify=False)
        Res = BeautifulSoup(Response.text)
        for elem in Res(text=Pattern):
            File.write((Link + " | Request Header | " + str(elem.parent) + " (Potential Vulnerable Location)\n"))
            print (Link + " | Request Header | " + str(elem.parent) + " (Potential Vulnerable Location)")
        ResetHeader()
    except Exception, e:
        ResetHeader()
        File.write(Link + " | " + str(e) + "\n")
        print (Link + " | " + str(e))


def PrintResponseHeaders(Link, Response, String):
    StatusCode = Response.status_code
    for header in HeaderList:
        try:
            Result = Response.headers[header]
            Res = BeautifulSoup(Response.text)

            if "30" in str(StatusCode) or "200" in str(StatusCode):
                if 'Via' in header or 'X-Powered-By' in header:
                    File.write("%s | (%s) %s | %s | %s (Potential Vulnerable Location)\n" % (Link, StatusCode, String, header, Result))
                    print ("%s | (%s) %s | %s | %s (Potential Vulnerable Location)" % (Link, StatusCode, String, header, Result))
                else:
                    File.write("%s | (%s) %s | %s | %s\n" % (Link, StatusCode, String, header, Result))
                    print ("%s | (%s) %s | %s | %s" % (Link, StatusCode, String, header, Result))

            else:
                for elem in Res(text=Pattern):
                    File.write("%s | (%s) %s | %s | %s (Potential Vulnerable Location)\n" % (
                        Link, StatusCode, String, header, Result))
                    print ("%s | (%s) %s | %s | %s (Potential Vulnerable Location)" % (
                    Link, StatusCode, String, header, Result))
        except:
            pass

def ResetHeader():
    global Headers
    Headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'}

Urls = ['192.168.0.7']
for Url in Urls:
    File.write(Url + "\n")
    print (Url)
    ChangeMethod(Url)
    # PageNotFound(Url)
    # ChangeProtocol(Url)
    # AddHeaders(Url)
    File.write("##########################\n\n")
    print ("##########################\n")

File.close()
