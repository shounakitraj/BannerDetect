# BannerDetect

Banner Grabing tool by Shounak Itraj

### How to Use:

1. Edit 'Urls' array in GrabBanners.py file.
2. Add URL for which you want grab banners.

### Installation:

Type the following in the terminal.

git clone https://github.com/shounakitraj/BannerDetect.git /opt/bannerdetect

This tool works on Python 2.7 and you should have Beautifulsoup installed.

|Library|Ubuntu|Windows|
|:----------:|:-------------:|:------:|
|BeautifulSoup|pip install BeautifulSoup|C:\Python27\Scripts\easy_install.exe BeautifulSoup|

### Description:

1. If the page gets redirected during visiting any of the Servers, it runtime maintains the list `Urls` for the redirected Urls.
2. The script reads whole list of Redirected Urls.
3. The output will be stored in `ReconOutput.txt` file. This file gets created in the same directory. 
4. This Version of script checks following conditions:

* Change of HTTP Method
* Visiting Non-existing page (To generate 404 condition)
* Changing HTTP protocol. E.g. Use **HTPT/1.1** instead of **HTTP/1.1**
* Changing HTTP Protocol version. E.g. Use **HTTP/3.0**

Ref: https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002)

This tool connects to the domains provided in the `urls`, creates the URL in format 'https://<ServerName>/'. Then uses this URL for testing if any banners/versions are displayed by the server.
Web Server sometimes may reveal its version if the unexpected/malformed request is sent. We have used following methods to check if version can be grabbed. The functions written in this tool parses both Response Headers and Response Body. If it matches with some pre-defined regex then the respective header or respective HTML tag is shown in output.

Pre-defined Regex:

```apache|JSP Engine|jetty|php|ssl``

### Change Method
In this function request is send to Server with different methods. If the Server is not configured correctly then it may reveal the version information in the response. Following methods are used for testing.

1. GET
2. POST
3. PUT
4. TRACE

### Visiting Non-existing page
Server version can be grabbed in 404 error page. This function is written to visit some random page which is unlikely present on any Server.

### Changing HTTP protocol or its version
According to OWASP document, sending malformed requests like changing HTTP protocol Name/Verb of Version is one of the useful test cases for determining Server version.
