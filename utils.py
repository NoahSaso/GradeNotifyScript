import csv
import os.path
import re
import smtplib
import urllib
import urlparse

def send_email(smtp_address, smtp_username, smtp_password, address, subject, message):
    """sends an email using the smtp account info specifed in config"""
    send_info = "From: %s\nTo: %s\nSubject: %s\nX-Mailer: ICGrades\n\n" % (smtp_username, address, subject)

    server = smtplib.SMTP(smtp_address)
    server.ehlo()
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(smtp_address, address, send_info + message)
    server.quit()

def url_fix(s, charset='utf-8'):
    """fixes spaces and query strings in urls, borrowed from werkzeug"""
    if isinstance(s, unicode):
        s = s.encode(charset, 'ignore')
    scheme, netloc, path, qs, anchor = urlparse.urlsplit(s)
    path = urllib.quote(path, '/%')
    qs = urllib.quote_plus(qs, ':&=')
    return urlparse.urlunsplit((scheme, netloc, path, qs, anchor))

def between(left,right,s):
    """searches for text between left and right

    >>> between('tfs', 'gsa', 'tfsaskdfnsdlkfjkldsfjgsa')
    'askdfnsdlkfjkldsfj'
    """
    before,_,a = s.partition(left)
    a,_,after = a.partition(right)
    return a
