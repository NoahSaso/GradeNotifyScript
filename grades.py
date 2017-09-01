#!/usr/bin/env python

import yaml
import json
import cookielib
import mechanize
import os
import string
import sys
import re
import sqlite3
import traceback
import logging
import time
import getpass
import utils

from BeautifulSoup import BeautifulSoup
from datetime import date, timedelta, datetime
from optparse import OptionParser
from xml.dom import minidom
from binascii import hexlify, unhexlify

from simplecrypt import encrypt, decrypt

DIRNAME = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_NAME = DIRNAME+"/config.yml"
cfg = {}

br = mechanize.Browser()
date = date.today()

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# Connect to SQLite 3
conn = sqlite3.connect(DIRNAME+"/history.db")
conn.row_factory = dict_factory
sqlc = conn.cursor()

parser = OptionParser(description='Scrapes grades from infinite campus website')
parser.add_option('-u', '--username', action='store', dest='username', help='specify username to check (probably student id)')
parser.add_option('-p', '--password', action='store', dest='password', help='password for account')
parser.add_option('-e', '--email', action='store', dest='email', help='if given with username and password, email results to this email')
parser.add_option('-n', '--noemail', action='store_true', dest='noemail', help='force to not send email even if grade changed')
parser.add_option('-s', '--setup', action='store_true', dest='setup', help='Setup accounts database')

# Example argument: '{"name": "Noah Saso", "username": "USERNAME_HERE", "password": "PASSWORD_HERE", "email": "noahsaso@gmail.com"}'
parser.add_option('-a', '--add', action='store', dest='add', metavar='USER_DICTIONARY', help='Adds user or enables if already exists')

parser.add_option('-d', '--disable', action='store', dest='disable', metavar='USERNAME', help='Disables user')

# Example argument: '{"username": "USERNAME_HERE", "key": "email", "value": "new_email@gmail.com"}'
parser.add_option('-m', '--modify', action='store', dest='modify', metavar='USER_DICTIONARY', help='Modifies attribute of user')

parser.add_option('-g', '--get', action='store_true', dest='get', help='Get list of users')
parser.add_option('-z', '--salt', action='store', dest='z', help='Encryption salt')

(options, args) = parser.parse_args()

class Course:
    """an object for an individual class, contains a grade and class name"""
    def __init__(self, name, grade, letter_grade):
        self.grade = grade
        self.name = name
        self.letter_grade = letter_grade

    def diff_grade(self, user, sqlc):
        """returns the difference between the current class grade
        and the last one
        """
        sqlc.execute("SELECT * FROM {} WHERE name = '{}'".format("user_"+user.username, self.name))
        course_row = sqlc.fetchone()
        new_grade = (self.grade if not course_row else course_row['grade'])
        return float(self.grade) - float(new_grade)

class User:
    @classmethod
    def get_all_users(self):
        sqlc.execute("SELECT * FROM accounts")
        users = []
        for user_row in sqlc.fetchall():
            users.append(User.from_dict(user_row))
        return users
    
    @classmethod
    def setup_accounts_table(self):
        sqlc.execute("CREATE TABLE IF NOT EXISTS accounts (username TEXT UNIQUE, name TEXT, email TEXT, password TEXT, enabled INTEGER)")
        conn.commit()

    @classmethod
    def from_username(self, username):
        sqlc.execute("SELECT * FROM accounts WHERE username = '{}'".format(username))
        user_row = sqlc.fetchone()
        if not user_row:
            return None
        else:
            return User.from_dict(user_row)
    
    @classmethod
    def from_dict(self, row):
        user = self()
        user.username = row['username']
        user.name = row.get('name', 'No Name')
        user.email = row.get('email', 'No Email')
        user.password = row['password']
        user.enabled = row.get('enabled', 1)
        return user
    
    @classmethod
    def from_attributes(self, username, name, password):
        user = self()
        user.username = username
        user.name = name
        user.email = None
        user.password = password
        user.enabled = 1
        return user
    
    @classmethod
    def exists(self, username):
        sqlc.execute("SELECT COUNT(*) FROM accounts WHERE username = '{}'".format(username))
        rows = sqlc.fetchone()['COUNT(*)']
        return rows > 0
    
    def create_account(self):
        sqlc.execute("INSERT INTO accounts VALUES ('{}', '{}', '{}', '{}', '{}')".format(self.username, self.name, self.email, self.password, 1))
        conn.commit()

    @classmethod
    def enable_account(self, username):
        sqlc.execute("UPDATE accounts SET enabled = '{}' WHERE username = '{}'".format(1, username))
        conn.commit()
        return User.from_username(username)
    
    @classmethod
    def disable_account(self, username):
        sqlc.execute("UPDATE accounts SET enabled = '{}' WHERE username = '{}'".format(0, username))
        conn.commit()
        return User.from_username(username)
    
    def create_row_if_not_exists(self):
        sqlc.execute("CREATE TABLE IF NOT EXISTS {} (name TEXT UNIQUE, grade FLOAT, letter TEXT, date DATE)".format("user_"+self.username))
        conn.commit()
    
    def update(self, key, value):
        sqlc.execute("UPDATE accounts SET {} = '{}' WHERE username = '{}'".format(key, value, self.username))
        setattr(self, key, value)
        conn.commit()

    def save_grades_to_database(self, grades):
        for course in grades:
            sqlc.execute("INSERT OR REPLACE INTO {} VALUES ('{}', '{}', '{}', '{}')".format("user_"+self.username, course.name, course.grade, course.letter_grade, date.today()))
            conn.commit()

    def __str__(self):
        return "{} ({}) [{}]".format(self.name, self.username, self.email)

def setup():
    """general setup commands"""
    
    # Setup config
    global cfg
    with open(CONFIG_FILE_NAME, 'r') as cfgfile:
        cfg = yaml.load(cfgfile)

    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)

    # Browser options
    br.set_handle_equiv(True)
    br.set_handle_redirect(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)

    # Follows refresh 0 but not hangs on refresh > 0
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

    # User-Agent
    br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

def get_base_url():
    """returns the site's base url, taken from the login page url"""
    return cfg['login_url'].split("/campus")[0] + '/campus/'

def get_schedule_page_url():
    """returns the url of the schedule page"""
    url = 'portal/portalOutlineWrapper.xsl?x=portal.PortalOutline&contentType=text/xml&lang=en'
    school_data = br.open(get_base_url() + url)
    dom = minidom.parse(school_data)

    nodes = dom.getElementsByTagName('Student')
    if nodes.count < 1:
        return False
    node = nodes[0]

    person_id = node.getAttribute('personID')
    first_name = node.getAttribute('firstName')
    last_name = node.getAttribute('lastName')

    nodes = dom.getElementsByTagName('Calendar')
    if nodes.count < 1:
        return False
    node = nodes[0]
    school_id = node.getAttribute('schoolID')

    nodes = dom.getElementsByTagName('ScheduleStructure')
    if nodes.count < 1:
        return False
    node = nodes[0]
    calendar_id = node.getAttribute('calendarID')
    structure_id = node.getAttribute('structureID')
    calendar_name = node.getAttribute('calendarName')

    return utils.url_fix(get_base_url() + u"portal/portal.xsl?x=portal.PortalOutline&lang=en&personID={}&studentFirstName={}&lastName={}&firstName={}&schoolID={}&calendarID={}&structureID={}&calendarName={}&mode=schedule&x=portal.PortalSchedule&x=resource.PortalOptions".format(
        person_id,
        first_name,
        last_name,
        first_name,
        school_id,
        calendar_id,
        structure_id,
        calendar_name))

def get_class_links(term):
    """loops through the links in the schedule page
    and adds the grade page links to the link_list array
    """
    r = br.open(get_schedule_page_url())
    soup = BeautifulSoup(r)
    table = soup.find('table', cellpadding=2, bgcolor='#A0A0A0')

    # Get links to stuff
    link_list = []
    for row in table.findAll('tr')[1:get_num_blocks()+2]:
        # Use term array and determine afterwards to use first or second term
        terms = []
        for col in row.findAll('td'):
            atag = col.find('a')
            if not atag:
                continue
            link = atag['href']
            if 'mailto' in link:
                link = None
            terms.append(link)
        # Choose which term to use based on current term (leaving -1 to signify that term is not the index, it's 1 or 2)
        if terms and term-1 <= len(terms)-1:
            link_list.append(terms[term-1])
    return link_list

def get_term():
    """returns the current term"""
    r = br.open(get_schedule_page_url()) #opens schdule page
    soup = BeautifulSoup(r)
    terms = soup.findAll('th', {'class':'scheduleHeader'}, align='center')
    term_dates = []
    for term in terms:
        if "(" in term.text:
            date_begin, date_end = utils.between('(', ')', term.text).split('-')
            string_to_date = lambda string: datetime.strptime(string, '%m/%d/%y')
            term_dates.append([string_to_date(date_begin), string_to_date(date_end)])
    now = datetime.now()
    if len(term_dates) == 1:
        return 1
    elif len(term_dates) == 2:
        if (term_dates[0][0] <= now <= term_dates[0][1]) or (term_dates[0][1] <= now <= term_dates[1][0]):
            return 1
        else:
            return 2
    else:
        return -1

def get_num_blocks():
    """returns the number of blocks per day"""
    schedule_page = br.open(get_schedule_page_url()) #opens schdule page
    soup = BeautifulSoup(schedule_page)
    blocks = soup.findAll('th', {'class':'scheduleHeader'}, align='center')
    count = 0
    for block in blocks:
        if "(" not in block.text:
            count += 1
    return count

def parse_page(url_part):
    """parses the class page at the provided url and returns a course object for it"""
    page = br.open(get_base_url() + url_part)
    soup = BeautifulSoup(page)
    grade = 0.0
    letter_grade = ''

    # Based on 2 semester per year system
    # Must change if using trimesters or quarters
    # Semester grade
    atag = soup.findAll(name='a', title=re.compile(r"^Task: Semester Grade"), limit=1)[0]
    # if it doesn't exist, try progress report 2
    spans = atag.findAll(name='span', attrs={'class':'grayText'}, limit=1)
    if len(spans) > 0:
        letter_grade = atag.contents[0].split('<br')[0]
    else:
        atag = soup.findAll(name='a', title=re.compile(r"^Task: Progress Grade 2"), limit=1)[0]
        # If it doesn't exist, try progress report 1
        spans = atag.findAll(name='span', attrs={'class':'grayText'}, limit=1)
        if len(spans) > 0:
            letter_grade = atag.contents[0].split('<br')[0]
        else:
            atag = soup.findAll(name='a', title=re.compile(r"^Task: Progress Grade 1"), limit=1)[0]
            spans = atag.findAll(name='span', attrs={'class':'grayText'}, limit=1)
            if len(spans) > 0:
                letter_grade = atag.contents[0].split('<br')[0]

    if len(spans) < 1:
        grade = -1.0
    else:
        grade = float(spans[0].string[:-1])

    course_name = soup.findAll(name='div', attrs={'class':'gridTitle'}, limit=1)[0].string
    course_name = string.replace(course_name, '&amp;', '&')
    course_name = course_name.strip()
    course_name = course_name.split(' ', 1)[1]
    return Course(course_name, grade, letter_grade)

def get_grades():
    """opens all pages in the link_list array and adds
    the last grade percentage and the corresponding class name
    to the grades list
    """
    try:
        grades = []
        print("Grabbing semester...")
        term = get_term()
        if term == -1:
            print("Failed to get term, ignoring person")
            return False
        else:
            print("Grabbing schedule...")
            class_links = get_class_links(term)
            print("Grabbing grades of schedule from semester...")
            for num, link in enumerate(class_links):
                if link is not None:
                    grades.append(parse_page(link))
            print("Got all grades...")
            return grades
    except:
        print("Something bad happened (probably login information failed?)")
        traceback.print_exc()
        #sys.exit(1)

    return False

def login(user, shouldDecrypt):
    """Logs in to the Infinite Campus at the
    address specified in the config
    """
    print("Logging in {}...".format(user))
    br.open(cfg['login_url'])
    br.select_form(nr=0) #select the first form
    br.form['username'] = user.username
    br.form['password'] = decrypt(options.z, unhexlify(user.password)).decode('utf8') if shouldDecrypt else user.password
    br.submit()

# returns array where index 0 element is grade_changed (boolean) and index 1 element is grade string
def get_grade_string(grades, user):
    """Extracts the grade_string"""
    changed_grade_string = ''
    other_grade_string = ''
    grade_changed = False
    for c in grades:
        if c.grade >= 0.0:
            if c.grade >= 100.0:
                grade_string = "{:.1f}% [{}] {}-- {}".format(c.grade, c.letter_grade, (' ' if len(c.letter_grade) is 1 else ''), c.name)
            else:
                grade_string = "{:.2f}% [{}] {}-- {}".format(c.grade, c.letter_grade, (' ' if len(c.letter_grade) is 1 else ''), c.name)
            diff = c.diff_grade(user, sqlc)
            if diff and diff < 100.0:
                grade_changed = True
                change_word = ('up' if diff > 0.0 else 'down')
                changed_grade_string += "\n".join([ grade_string,
                                                    "" + change_word + " " + str(abs(diff)) + "% (old: " + str(c.grade - diff) + "%)",
                                                  ])
            else:
                other_grade_string += grade_string + "\n"
    return [grade_changed, (changed_grade_string + other_grade_string)]

def send_grade_email(email, message):
    print("Sending email to {}".format(email))
    utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], email, 'Grade Alert', message)

def main():
    # Run every 10 minutes with a cron job (*/10 * * * * /path/to/scraper_auto.py)
    try:
        setup()

        if options.setup:
            User.setup_accounts_table()
            print("Setup accounts database")
        elif options.add or options.modify:
            user_data = json.loads(options.add or options.modify)
            username = user_data['username'] or 'EMPTY_USER'
            if username is 'EMPTY_USER':
                print("Please provide a username to add or modify")
            else:
                if User.exists(username):
                    if options.add:
                        user = User.enable_account(username)
                        print("Enabled {}".format(user))
                    else:
                        user = User.from_username(username)
                        new_value = user_data['value']
                        if user_data['key'] == 'password':
                            if options.z:
                                new_value = hexlify(encrypt(options.z, new_value.encode('utf8')))
                            else:
                                print("Please include the encryption salt")
                                return
                        user.update(user_data['key'], new_value)
                        print("Updated {} for {}".format(user_data['key'], user))
                elif options.add:
                    if all (k in user_data for k in ("name", "password", "email")):
                        # If forgot encryption salt, tell them
                        if not options.z:
                            print("Please include the encryption salt")
                        else:
                            user = User.from_dict(user_data)
                            user.password = hexlify(encrypt(options.z, user.password.encode('utf8')))
                            user.create_account()
                            print("Created {}".format(user))
                    else:
                        print("Please provide name, username, password, and email")
                elif options.modify:
                    print("This user does not exist")
        elif options.disable:
            if not User.exists(options.disable):
                print("Could not find user with given username ({})".format(options.disable))
            else:
                user = User.disable_account(options.disable)
                print("Disabled {}".format(user))
        elif options.get:
            disabled_users = []
            enabled_users = []
            for user in User.get_all_users():
                if user.enabled == 1:
                    enabled_users.append(str(user))
                else:
                    disabled_users.append(str(user))
            final_string = "\n".join([  "DISABLED:\n",
                                        "\n".join(sorted(disabled_users, key=str.lower) or ['No disabled users']),
                                        "\nENABLED:\n",
                                        "\n".join(sorted(enabled_users, key=str.lower) or ['No enabled users'])
                                    ])
            print(final_string)
        else:
            # If gave username but no password or vice versa
            if (options.username and not options.password) or (options.password and not options.username):
                print("Please provide both the username and password for this account to check.")
            # If neither username nor password given, do loop of all
            elif not options.username and not options.password:
                # If forgot encryption salt, tell them
                if not options.z:
                    print("Please include the encryption salt")
                else:
                    # Get users
                    for user in User.get_all_users():

                        login(user, True)

                        grades = get_grades()
                        if grades == False:
                            print("Something went wrong")
                            continue

                        user.create_row_if_not_exists()
                        user.save_grades_to_database(grades)

                        # Print before saving to show changes
                        final_grades = get_grade_string(grades, user)
                        # If grade changed and no send email is false, send email
                        if options.email or (not options.noemail and final_grades[0]):
                            send_grade_email(user.email, final_grades[1])

                        print(final_grades[1])

            # Else if specified username + password
            else:
                user = User.from_attributes(options.username, 'User', options.password)

                login(user, False)

                grades = get_grades()
                if grades == False:
                    print("Something went wrong")
                else:

                    user.create_row_if_not_exists()
                    user.save_grades_to_database(grades)

                    final_grades = get_grade_string(grades, user)
                    if options.email:
                        send_grade_email(options.email, final_grades[1])

                    print(final_grades[1])

        sqlc.close()
        conn.close()

    except:
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)

if __name__ == '__main__':
    main()
