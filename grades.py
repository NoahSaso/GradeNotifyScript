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

DEV_MODE = getpass.getuser() != 'gradenotify'
def dev_print(string):
    if DEV_MODE:
        print(string)

DIRNAME = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_NAME = DIRNAME+"/config.yml"
cfg = {}

br = mechanize.Browser()

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# Connect to SQLite 3
conn = sqlite3.connect(DIRNAME+"/database.db")
conn.row_factory = dict_factory
sqlc = conn.cursor()

curr_user = None

parser = OptionParser(description='Scrapes grades from infinite campus website')

# USER
# Example argument: '{"name": "Noah Saso", "username": "STUDENT_ID_HERE", "password": "PASSWORD_HERE", "email": "EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-a', '--add', action='store', dest='add', metavar='USER_DICTIONARY', help='Adds user')
parser.add_option('-e', '--enable', action='store', dest='enable', metavar='STUDENT_ID', help='Enables user')
parser.add_option('-d', '--disable', action='store', dest='disable', metavar='STUDENT_ID', help='Disables user')
parser.add_option('-r', '--remove', action='store', dest='remove', metavar='STUDENT_ID', help='Removes user from database')
# Example argument: '{"username": "USERNAME_HERE", "key": "email", "value": "NEW_EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-m', '--modify', action='store', dest='modify', metavar='USER_DICTIONARY', help='Modifies attribute of user')
parser.add_option('-x', '--exists', action='store', dest='exists', metavar='STUDENT_ID', help='Returns if user exists')
parser.add_option('-l', '--list', action='store_true', dest='list', help='Get list of users')
# Example argument: '{"username": "USERNAME_HERE", "password": "PASSWORD_HERE", "email": "EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-c', '--check', action='store', dest='check', metavar='USER_DICTIONARY', help='Check specific user')
# Example argument: '{"username": "USERNAME_HERE", "password": "PASSWORD_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-v', '--valid', action='store', dest='valid', metavar='USER_DICTIONARY', help='Verify username and password valid pair')
parser.add_option('-g', '--go', action='store', dest='go', metavar='STUDENT_ID', help='Sends grades to user')
parser.add_option('-y', action='store_true', dest='createall', help='Creates database for all users in accounts table if not exist')

# OTHER
parser.add_option('-q', '--quiet', action='store_true', dest='quiet', help='force to not send email even if grade changed')
parser.add_option('-o', '--loud', action='store_true', dest='loud', help='force to send email even if grade not changed')
parser.add_option('-s', '--setup', action='store_true', dest='setup', help='Setup accounts database')
parser.add_option('-z', '--salt', action='store', dest='z', help='Encryption salt')
# Example argument: '{"username": "STUDENT_ID_HERE", "password": "PASSWORD_HERE"}'
parser.add_option('-i', '--infinitecampus', action='store', dest='infinitecampus', metavar='USER_DICTIONARY', help='Check validity of infinite campus credentials')

(options, args) = parser.parse_args()

def encrypted(string):
    return hexlify(encrypt(options.z, string.encode('utf8')))

def decrypted(string):
    return decrypt(options.z, unhexlify(string)).decode('utf8')

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
        sqlc.execute("SELECT * FROM '{}' WHERE name = '{}'".format("user_"+user.student_id, self.name))
        course_row = sqlc.fetchone()
        # Set prev grade to own grade so no difference if grade didn't exist
        prev_grade = (course_row['grade'] if course_row and 'grade' in course_row else self.grade)
        if prev_grade < 0.0:
            return False
        return float(self.grade) - float(prev_grade)

class User:
    @classmethod
    def get_all_users(self, where_clause):
        sqlc.execute("SELECT * FROM accounts{}".format(" {}".format(where_clause) if where_clause else ''))
        users = []
        for user_row in sqlc.fetchall():
            users.append(User.from_dict(user_row))
        return users
    
    @classmethod
    def setup_accounts_table(self):
        sqlc.execute("CREATE TABLE IF NOT EXISTS accounts (username TEXT, name TEXT, email TEXT, password TEXT, enabled INTEGER, student_id TEXT UNIQUE)")
        conn.commit()

    @classmethod
    def from_student_id(self, student_id):
        sqlc.execute("SELECT * FROM accounts WHERE student_id = '{}'".format(student_id))
        user_row = sqlc.fetchone()
        if not user_row:
            return None
        else:
            return User.from_dict(user_row)
    
    @classmethod
    def from_dict(self, row):
        user = self()
        user.username = row['username']
        user.name = row.get('name', 'Unknown Name')
        user.email = row.get('email', '')
        user.password = row['password']
        user.enabled = row.get('enabled', 1)
        user.student_id = row['student_id']
        return user
    
    @classmethod
    def exists(self, student_id):
        sqlc.execute("SELECT COUNT(*) FROM accounts WHERE student_id = '{}'".format(student_id))
        rows = sqlc.fetchone()['COUNT(*)']
        return rows > 0
    
    def create_account(self):
        sqlc.execute("INSERT INTO accounts VALUES ('{}', '{}', '{}', '{}', '{}', '{}')".format(self.username, self.name, self.email, self.password, 1, self.student_id))
        conn.commit()
        self.create_table_if_not_exists()

    @classmethod
    def enable_account(self, student_id):
        sqlc.execute("UPDATE accounts SET enabled = '{}' WHERE student_id = '{}'".format(1, student_id))
        conn.commit()
        return User.from_student_id(student_id)
    
    @classmethod
    def disable_account(self, student_id):
        sqlc.execute("UPDATE accounts SET enabled = '{}' WHERE student_id = '{}'".format(0, student_id))
        conn.commit()
        return User.from_student_id(student_id)
    
    @classmethod
    def remove_account(self, student_id):
        user = User.from_student_id(student_id)
        sqlc.execute("DELETE FROM accounts WHERE student_id = '{}'".format(student_id))
        conn.commit()
        return user
    
    @classmethod
    def valid_password(self, student_id, password):
        sqlc.execute("SELECT password FROM accounts WHERE student_id = '{}'".format(student_id))
        password_row = decrypted(sqlc.fetchone()['password'])
        return password == password_row
    
    def create_table_if_not_exists(self):
        sqlc.execute("CREATE TABLE IF NOT EXISTS '{}' (name TEXT UNIQUE, grade FLOAT, letter TEXT)".format("user_"+self.student_id))
        conn.commit()
    
    def update(self, key, value):
        sqlc.execute("UPDATE accounts SET {} = '{}' WHERE student_id = '{}'".format(key, value, self.student_id))
        setattr(self, key, value)
        conn.commit()

    def save_grades_to_database(self, grades):
        for course in grades:
            sqlc.execute("INSERT OR REPLACE INTO {} VALUES ('{}', '{}', '{}')".format("user_"+self.student_id, course.name, course.grade, course.letter_grade))
            conn.commit()

    def __str__(self):
        return "{} ({} -- {}) [{}]".format(self.name, self.username, self.student_id, self.email)

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

def get_portal_data():
    url = 'portal/portalOutlineWrapper.xsl?x=portal.PortalOutline&contentType=text/xml&lang=en'
    school_data = br.open(get_base_url() + url)
    try:
        return minidom.parse(school_data)
    except:
        dev_print("Minidom failed parsing (probably not signed in)")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | minidom parse failed", "{}\n\n{}".format(curr_user, full))
        return False

def get_schedule_page_url():
    """returns the url of the schedule page"""
    if not curr_user:
        return False

    dom = get_portal_data()
    if not dom:
        return False

    nodes = dom.getElementsByTagName('Student')
    node = False
    for student in nodes:
        if not student.hasAttribute('studentNumber'):
            continue
        curr_student_id = student.getAttribute('studentNumber')
        if curr_student_id == curr_user.student_id:
            node = student
            break
    if not node:
        print("Account does not have this student ID")
        return False

    person_id = node.getAttribute('personID')
    first_name = node.getAttribute('firstName')
    last_name = node.getAttribute('lastName')

    nodes = dom.getElementsByTagName('Calendar')
    if len(nodes) < 1:
        return False
    node = nodes[0]
    school_id = node.getAttribute('schoolID')

    nodes = dom.getElementsByTagName('ScheduleStructure')
    if len(nodes) < 1:
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
    schedule_page_url = get_schedule_page_url()
    if not schedule_page_url:
        return False
    r = br.open(schedule_page_url)
    soup = BeautifulSoup(r)
    table = soup.find('table', cellpadding=2, bgcolor='#A0A0A0')

    # Get links to stuff
    link_list = []
    num_blocks = get_num_blocks()
    if num_blocks == False:
        return False
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
    if not curr_user:
        return False
    schedule_page_url = get_schedule_page_url()
    if not schedule_page_url:
        return -1
    r = br.open(schedule_page_url)
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
    schedule_page_url = get_schedule_page_url()
    if not schedule_page_url:
        return False
    r = br.open(schedule_page_url)
    soup = BeautifulSoup(r)
    blocks = soup.findAll('th', {'class':'scheduleHeader'}, align='center')
    count = 0
    for block in blocks:
        if "(" not in block.text:
            count += 1
    return count

def course_from_page(url_part):
    """parses the class page at the provided url and returns a course object for it"""
    page = br.open(get_base_url() + url_part)
    soup = BeautifulSoup(page)
    grade = 0.0
    letter_grade = ''

    # Based on 2 semester per year system
    # Must change if using trimesters or quarters
    # Semester grade
    atags = soup.findAll(name='a', title=re.compile(r"^Task: Semester Grade"), limit=1)
    if len(atags) < 1:
        return False
    atag = atags[0]
    # if it doesn't exist, try progress report 2
    spans = atag.findAll(name='span', attrs={'class':'grayText'}, limit=1)
    if len(spans) > 0:
        letter_grade = atag.contents[0].split('<br')[0]
    else:
        atags = soup.findAll(name='a', title=re.compile(r"^Task: Progress Grade 2"), limit=1)
        if len(atags) < 1:
            return False
        atag = atags[0]
        # If it doesn't exist, try progress report 1
        spans = atag.findAll(name='span', attrs={'class':'grayText'}, limit=1)
        if len(spans) > 0:
            letter_grade = atag.contents[0].split('<br')[0]
        else:
            atags = soup.findAll(name='a', title=re.compile(r"^Task: Progress Grade 1"), limit=1)
            if len(atags) < 1:
                return False
            atag = atags[0]
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
    print("Getting grades...")
    if not curr_user:
        return False
    curr_user.create_table_if_not_exists()
    try:
        grades = []
        term = get_term()
        if term == -1:
            dev_print("Failed to get term, maybe password issue, ignoring user")
            return False
        else:
            dev_print("Grabbing schedule...")
            class_links = get_class_links(term)
            if not class_links:
                return False
            dev_print("Grabbing grades of schedule from semester...")
            for num, link in enumerate(class_links):
                if link is not None:
                    course = course_from_page(link)
                    if course:
                        grades.append(course)
            dev_print("Got all grades...")
            return grades
    except:
        dev_print("Something bad happened (probably login information failed?)")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | get_grades try failed", "{}\n\n{}".format(curr_user, full))

    return False

def login(user, shouldDecrypt):
    """Logs in to the Infinite Campus at the
    address specified in the config
    """
    try:

        br.open(cfg['login_url'])
        br.select_form(nr=0) #select the first form
        br.form['username'] = user.username
        br.form['password'] = decrypted(user.password) if shouldDecrypt else user.password
        r = br.submit()

        soup = BeautifulSoup(r)

        # shows if sign in failed
        # error_msg = soup.find('p', {'class': 'errorMessage'})
        # status_msg = soup.find('div', {'class': 'statusmsg'})
        # if status_msg:
        #     status_error = 'Incorrect' in status_msg.getText()
        # else:
        #     status_error = False

        iframe = soup.find('iframe', id='frameDetail', attrs={'name': 'frameDetail'})

        global curr_user
        # if not error_msg and not status_error:
        if iframe:

            dom = get_portal_data()
            if not dom:
                curr_user = None
            else:
                students = dom.getElementsByTagName('Student')
                exists = False
                for student in students:
                    if not student.hasAttribute('studentNumber'):
                        continue
                    curr_student_id = student.getAttribute('studentNumber')
                    if curr_student_id == user.student_id:
                        exists = True
                        break
                if exists:
                    curr_user = user
                    return True
                    
        else:
            curr_user = None
        
    except (mechanize.HTTPError, mechanize.URLError) as e:
        print("Could not connect to Infinite Campus' servers. Please try again later when it is back up so your credentials can be verified.")
    
    return False

def logout():
    """Logs out of Infinite Campus
    """
    br.open(get_base_url() + 'logoff.jsp')

    global curr_user
    curr_user = None

# returns array where index 0 element is grade_changed (boolean) and index 1 element is grade string
def get_grade_string(grades, user, inDatabase):
    """Extracts the grade_string"""
    final_grades = ""
    grade_changed = False
    for c in grades:
        if c.grade >= 0.0:
            if c.grade >= 100.0:
                grade_string = "{:.1f}% [{}] {}-- {}".format(c.grade, c.letter_grade, (' ' if len(c.letter_grade) is 1 else ''), c.name)
            else:
                grade_string = "{:.2f}% [{}] {}-- {}".format(c.grade, c.letter_grade, (' ' if len(c.letter_grade) is 1 else ''), c.name)
            diff = False
            if inDatabase:
                diff = c.diff_grade(user, sqlc)
            if diff:
                grade_changed = True
                change_word = ('up' if diff > 0.0 else 'down')
                final_grades += "\n".join([grade_string + " [" + change_word + " " + str(abs(diff)) + "% from " + str(c.grade - diff) + "%]", ""])
            else:
                final_grades += grade_string + "\n"
    if grade_changed:
        print("A grade changed")

    return [grade_changed, final_grades]

def send_grade_email(email, message):
    print("Sending grade email to {}".format(email))
    utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], email, 'Grade Alert', message)

def send_welcome_email(user):

    first_name = user.name.split(' ')
    if len(first_name) > 0:
        first_name = first_name[0]

    message = "\n".join([
        "Hey {},".format(first_name),
        "",
        "You have signed up for GradeNotify. About every 30 minutes, the system will scan your grades and email you an update if anything is different from the previous scan. Right now, I only send the cumulative grades of each class (not individual assignments). More detailed reports will come soon.",
        "",
        "You can reply to this email if you have any questions or issues.",
        "",
        "Thanks!",
        "Noah -- Grade Notify"
    ])

    email = 'noahsaso@gmail.com' if DEV_MODE else user.email

    print("Sending welcome email to {} {{{}}}".format(user, email))
    utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], email, 'Welcome', message)

def send_admin_email(subject, message):
    if not DEV_MODE:
        utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], 'noahsaso@gmail.com', subject, message)

def main():
    # Run every 10 minutes with a cron job (*/10 * * * * /path/to/scraper_auto.py)
    try:
        setup()

        if options.setup:
            User.setup_accounts_table()
            print("Setup accounts database")
        # argument is dictionary with student_id
        elif options.valid or options.modify:
            user_data = json.loads(options.modify or options.valid)
            student_id = user_data['student_id'] if 'student_id' in user_data else False
            if not student_id:
                print("Please provide a student ID")
            else:
                if User.exists(student_id):
                    # USER EXISTS
                    if options.valid:
                        if not options.z:
                            print("Please include the encryption salt")
                            return
                        if "password" not in user_data:
                            print("Please provide the password")
                            return
                        print(("1" if User.valid_password(student_id, user_data['password']) else "0"))
                    elif options.modify:
                        if all (k in user_data for k in ("key", "value")):
                            user = User.from_student_id(student_id)
                            new_value = user_data['value']
                            if user_data['key'] == 'password':
                                if options.z:
                                    new_value = encrypted(new_value)
                                else:
                                    print("Please include the encryption salt")
                                    return
                            user.update(user_data['key'], new_value)
                            send_admin_email("GN | User Updated", "Updated {} for {}".format(user_data['key'], user))
                            print("Updated {} for {}".format(user_data['key'], user))
                        else:
                            print("Please provide student_id, key, and value")
                else:
                    # USER DOES NOT EXIST
                    if options.valid:
                        print("0")
                    elif options.modify:
                        print("Could not find user with student_id '{}'".format(student_id))
        # argument is dictionary with username and student_id
        elif options.add or options.infinitecampus:
            user_data = json.loads(options.add or options.infinitecampus)
            username = user_data['username'] if 'username' in user_data else False
            student_id = user_data['student_id'] if 'student_id' in user_data else False
            if not username or not student_id:
                print("Please provide a username and student ID")
            else:
                if options.infinitecampus:
                    if 'password' in user_data:
                        user = User.from_dict(user_data)
                        print("1" if login(user, False) else "0")
                    else:
                        print("Please provide a username, password, and student_id")
                else:
                    if User.exists(student_id):
                        if options.add:
                            print("A user with student_id '{}' already exists. Please use the -e flag instead".format(student_id))
                    elif options.add:
                        if all (k in user_data for k in ("name", "password", "email")):
                            # If forgot encryption salt, tell them
                            if not options.z:
                                print("Please include the encryption salt")
                            else:
                                user = User.from_dict(user_data)
                                user.password = encrypted(user.password)
                                user.create_account()
                                send_admin_email("GN | User Created", "Created {}".format(user))
                                send_welcome_email(user)
                                print("Added {}".format(user))
                        else:
                            print("Please provide name, username, student_id, password, and email")
        # argument is student_id
        elif options.enable or options.disable or options.remove or options.exists:
            student_id = options.enable or options.disable or options.remove or options.exists
            if not User.exists(student_id):
                if options.enable or options.disable or options.remove:
                    print("Could not find user with student_id '{}'".format(student_id))
                elif options.exists:
                    print("0")
            else:
                if options.enable:
                    user = User.enable_account(student_id)
                    send_admin_email("GN | User Enabled", "Enabled {}".format(user))
                    print("Enabled {}".format(user))
                elif options.disable:
                    user = User.disable_account(student_id)
                    send_admin_email("GN | User Disabled", "Disabled {}".format(user))
                    print("Disabled {}".format(user))
                elif options.remove:
                    user = User.remove_account(student_id)
                    send_admin_email("GN | User Removed", "Removed {}".format(user))
                    print("Removed {}".format(user))
                elif options.exists:
                    print("1")
        elif options.list:
            disabled_users = []
            enabled_users = []
            for user in User.get_all_users(''):
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
        elif options.go:
            if not options.z:
                print("Please include the encryption salt")
            else:
                if User.exists(options.go):
                    do_task(User.from_student_id(options.go), True)
                else:
                    print("Could not find user with student_id {}".format(options.go))
        elif options.createall:
            for user in User.get_all_users(''):
                user.create_table_if_not_exists()
        else:
            # If not checking single
            if not options.check:
                # If forgot encryption salt, tell them
                if not options.z:
                    print("Please include the encryption salt")
                else:
                    # Get users
                    for user in User.get_all_users('WHERE enabled = 1'):
                        do_task(user, True)

            # Else if specified check user
            else:
                do_task(User.from_dict(json.loads(options.check)), False)

        sqlc.close()
        conn.close()

    except:
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | Main try failed", "{}".format(full))

def do_task(user, inDatabase):
    try:
        print("Logging in {}...".format(user))
        if not login(user, inDatabase):
            print("Log in failed, probably wrong credentials")
            send_admin_email("GN | Login failed", "{}".format(user))
            return

        grades = get_grades()
        if grades == False:
            return

        # Print before saving to show changes
        # array: [ grade_changed, string ]
        final_grades = get_grade_string(grades, user, inDatabase)
        # If grade changed and no send email is false, send email
        if (not inDatabase and user.email) or (inDatabase and (options.go or options.loud or (not options.quiet and final_grades[0]))):
            send_grade_email(user.email, final_grades[1])

        if inDatabase:
            user.save_grades_to_database(grades)

        dev_print(final_grades[1])

        logout()
    except:
        print("Doing task failed, probably login information failed?")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | do_task try failed", "{}\n\n{}".format(user, full))

if __name__ == '__main__':
    main()
