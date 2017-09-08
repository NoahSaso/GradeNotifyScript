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
import re

from BeautifulSoup import BeautifulSoup
from datetime import date, timedelta, datetime
from optparse import OptionParser
from xml.dom import minidom
from binascii import hexlify, unhexlify

import hashlib
import base64

from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:

    def __init__( self, key ):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

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
schedule_page_data = None
grade_page_data = None
dont_send_failed_login_email = False

NON_DECIMAL = re.compile(r'[^\d.]+')

parser = OptionParser(description='Scrapes grades from infinite campus website')

# USER
# Example argument: '{"name": "Noah Saso", "username": "STUDENT_ID_HERE", "password": "PASSWORD_HERE", "email": "EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-a', '--add', action='store', dest='add', metavar='USER_DICTIONARY', help='Adds user')
parser.add_option('-r', '--remove', action='store', dest='remove', metavar='STUDENT_ID', help='Removes user from database')
# Example argument: '{"username": "USERNAME_HERE", "key": "email", "value": "NEW_EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-m', '--modify', action='store', dest='modify', metavar='USER_DICTIONARY', help='Modifies attribute of user')
parser.add_option('-x', '--exists', action='store', dest='exists', metavar='STUDENT_ID', help='Returns if user exists')
parser.add_option('-l', '--list', action='store_true', dest='list', help='Get list of users')
# Example argument: '{"username": "USERNAME_HERE", "password": "PASSWORD_HERE", "email": "EMAIL_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-c', '--check', action='store', dest='check', metavar='USER_DICTIONARY', help='Check specific user')
# Example argument: '{"username": "USERNAME_HERE", "password": "PASSWORD_HERE", "student_id": "STUDENT_ID_HERE"}'
parser.add_option('-v', '--valid', action='store', dest='valid', metavar='USER_DICTIONARY', help='Verify username and password valid pair')
parser.add_option('-g', '--go', action='store', dest='go', metavar='STUDENT_ID:SEND', help='Sends grades to user')
parser.add_option('-y', action='store_true', dest='createall', help='Creates database for all users in accounts table if not exist')

# OTHER
parser.add_option('-q', '--quiet', action='store_true', dest='quiet', help='force to not send email even if grade changed')
parser.add_option('-o', '--loud', action='store_true', dest='loud', help='force to send email even if grade not changed')
parser.add_option('-s', '--setup', action='store_true', dest='setup', help='Setup accounts database')
parser.add_option('-z', '--salt', action='store', dest='z', help='Encryption salt')
# Example argument: '{"username": "STUDENT_ID_HERE", "password": "PASSWORD_HERE"}'
parser.add_option('-i', '--infinitecampus', action='store', dest='infinitecampus', metavar='USER_DICTIONARY', help='Check validity of infinite campus credentials')
# Example argument: '{"table": "TABLE_HERE", "method": "add_column", "name": "NAME_HERE", "type": "TYPE_HERE"}'
parser.add_option('-d', '--database', action='store', dest='database', metavar='DICTIONARY', help='Modify database')

(options, args) = parser.parse_args()

def encrypted(string):
    return hexlify(AESCipher(options.z).encrypt(string))

def decrypted(string):
    return AESCipher(options.z).decrypt(unhexlify(string))

class Course:
    """an object for an individual class, contains a grade and class name"""
    def __init__(self, name, grade, letter, last_assignment, user):
        self.grade = grade
        self.name = name
        self.letter = letter
        self.last_assignment = last_assignment
        self.user = user

    @classmethod
    def course_from_name(self, user, name):
        sqlc.execute("SELECT * FROM 'user_{}' WHERE name = '{}'".format(user.student_id, name))
        course_row = sqlc.fetchone()
        if course_row:
            try:
                last_assignment = json.loads(course_row.get('last_assignment', "{{}}"))
            except:
                last_assignment = {}
            return Course(course_row['name'], float(course_row['grade']), course_row['letter'], last_assignment, curr_user)
        else:
            return False
    
    def save(self):
        sqlc.execute("INSERT OR REPLACE INTO 'user_{}' VALUES ('{}', '{}', '{}', '{}')".format(self.user.student_id, self.name, self.grade, self.letter, json.dumps(self.last_assignment)))
        conn.commit()

    def diff_grade(self):
        """returns the difference between the current class grade
        and the last one
        """
        sqlc.execute("SELECT * FROM 'user_{}' WHERE name = '{}'".format(self.user.student_id, self.name))
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
        sqlc.execute("CREATE TABLE IF NOT EXISTS accounts (username TEXT, name TEXT, email TEXT, password TEXT, enabled INTEGER, student_id TEXT UNIQUE, premium INTEGER)")
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
        user.premium = row.get('premium', 0)
        user.phone_email = row.get('phone_email', '')
        return user
    
    @classmethod
    def exists(self, student_id):
        sqlc.execute("SELECT COUNT(*) FROM accounts WHERE student_id = '{}'".format(student_id))
        rows = sqlc.fetchone()['COUNT(*)']
        return rows > 0
    
    def create_account(self):
        sqlc.execute("INSERT INTO accounts VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(self.username, self.name, self.email, self.password, 1, self.student_id, 0))
        conn.commit()
        self.create_table_if_not_exists()
    
    @classmethod
    def remove_account(self, student_id):
        user = User.from_student_id(student_id)
        sqlc.execute("DELETE FROM accounts WHERE student_id = '{}'".format(student_id))
        conn.commit()
        return user
    
    @classmethod
    def valid_password(self, student_id, password):
        user = User.from_student_id(student_id)
        if user:
            password_row = decrypted(user.password)
            return password == password_row
        else:
            return False
    
    def create_table_if_not_exists(self):
        sqlc.execute("CREATE TABLE IF NOT EXISTS 'user_{}' (name TEXT UNIQUE, grade FLOAT, letter TEXT, last_assignment TEXT)".format(self.student_id))
        conn.commit()
    
    def update(self, key, value):
        sqlc.execute("UPDATE accounts SET {} = '{}' WHERE student_id = '{}'".format(key, value, self.student_id))
        conn.commit()
        setattr(self, key, value)

    def save_grades_to_database(self, grades):
        for course in grades:
            course.save()

    def __str__(self):
        return "{} ({} -- {}) [{} / {}] [{}]".format(self.name, self.username, self.student_id, self.email, self.phone_email, self.premium)

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
    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        dev_print("Minidom failed parsing (probably not signed in)")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | minidom parse failed", "{}\n\n{}".format(curr_user, full))
        return False

def get_page_url(gradesPage):
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
    
    if gradesPage:
        mode = 'grades'
        x = 'portal.PortalGrades'
    else:
        mode = 'schedule'
        x = 'portal.PortalSchedule'

    return utils.url_fix(get_base_url() + u"portal/portal.xsl?x=portal.PortalOutline&lang=en&personID={}&studentFirstName={}&lastName={}&firstName={}&schoolID={}&calendarID={}&structureID={}&calendarName={}&mode={}&x={}&x=resource.PortalOptions".format(
        person_id,
        first_name,
        last_name,
        first_name,
        school_id,
        calendar_id,
        structure_id,
        calendar_name,
        mode,
        x))

def get_all_grades():
    if not curr_user:
        return False
    soup = grade_page_data

    courses = []

    in_progress_grades = soup.findAll(name='td', attrs={'class':'inProgressGrade'})
    for in_prog_grade in in_progress_grades:
        contents = in_prog_grade.contents
        if len(contents) == 2:
            grade = NON_DECIMAL.sub('', contents[0])
            letter = contents[1].getText().strip()
            name = in_prog_grade.parent.parent.find('tr').find('td', attrs={'class': 'gradesLink'}).find('a').find('b').getText().strip() # td.inProgressGrade < tr < tbody > tr.find(td.gradesLink) > a > b
            # manipulate name
            name = name.replace('&amp;','&').split(' ')
            name.pop(0)
            name = " ".join(name)
            # get assignments
            # $('div#recentAssignments table.portalTable tbody tr')
            assignments = {}
            if curr_user.premium == 1:
                assignments_tables = soup.findAll(name='table', attrs={'class': 'portalTable'})
                if len(assignments_tables) < 2:
                    return False
                assignments_table = assignments_tables[1]
                for tr in assignments_table.find('tbody').findAll('tr'):
                    cont = tr.contents
                    if len(cont) < 14:
                        continue

                    course_name = cont[5].getText().replace('&amp;','&').split(' - ')
                    course_name.pop(0)
                    course_name = " - ".join(course_name)

                    if course_name not in assignments:
                        assignments[course_name] = []

                    assignment_name = cont[7].getText().strip()
                    score = NON_DECIMAL.sub('', cont[9].getText().strip())
                    total = NON_DECIMAL.sub('', cont[11].getText().strip())
                    percent = NON_DECIMAL.sub('', cont[13].getText().strip())
                    
                    assignments[course_name].append({ 'assignment_name': assignment_name, 'score': score, 'total': total, 'percent': percent })

                    # print("{} -- {} [{}/{}] ({})".format(course_name, assignment_name, score, total, percent))
            
            course = Course.course_from_name(curr_user, name)

            if not course:
                course = Course(name, float(grade), letter, {}, curr_user)
            
            if name in assignments:
                course_assignments = assignments[name]

                new_assignments = []
                if course.last_assignment and course.last_assignment in course_assignments:
                    index_of_last = course_assignments.index(course.last_assignment)
                    new_assignments = course_assignments[:index_of_last]
                else:
                    # course grade changed, search for just name if couldn't find whole thing
                    course_assignments_array = dict((a['assignment_name'], course_assignments.index(a)) for a in course_assignments)
                    if course.last_assignment and course.last_assignment['assignment_name'] in course_assignments_array:
                        index_of_last = course_assignments_array[course.last_assignment['assignment_name']]
                        index_with_prev_last = index_of_last + 1
                        new_assignments = course_assignments[:index_with_prev_last]
                
                course.last_assignment = course_assignments[0]
                course.new_assignments = new_assignments

            else:
                # dev_print("No assignments for {} (premium: {})".format(name, curr_user.premium))
                course.new_assignments = []

            # add course
            courses.append(course)
    return courses

def login(user, shouldDecrypt):
    """Logs in to the Infinite Campus at the
    address specified in the config
    """
    global dont_send_failed_login_email
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
        global schedule_page_data
        global grade_page_data
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

                    schedule_page_data = None
                    for idx in range(3):
                        schedule_page_data = br.open(get_page_url(False))
                        if schedule_page_data:
                            schedule_page_data = BeautifulSoup(schedule_page_data)
                            if schedule_page_data:
                                break
                    grade_page_data = None
                    for idx in range(3):
                        grade_page_data = br.open(get_page_url(True))
                        if grade_page_data:
                            grade_page_data = BeautifulSoup(grade_page_data)
                            if grade_page_data:
                                break

                    return True
                    
        else:
            curr_user = None

        dont_send_failed_login_email = False
        
    except KeyboardInterrupt:
        sys.exit()
    except (mechanize.HTTPError, mechanize.URLError) as e:
        print("Could not connect to Infinite Campus' servers. Please try again later when it is back up so your credentials can be verified.")
        dont_send_failed_login_email = True
    except Exception:
        print("Logging in failed")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | login try failed", "{}\n\n{}".format(user, full))
    
    return False

def logout():
    """Logs out of Infinite Campus
    """
    try:
        br.open(get_base_url() + 'logoff.jsp')

        global curr_user
        curr_user = None
    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        print("Logging out failed")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | logout try failed", "{}\n\n{}".format(curr_user, full))

# returns array where index 0 element is grade_changed (boolean) and index 1 element is grade string
def get_grade_string(grades, inDatabase, showAll):
    """Extracts the grade_string"""
    if not curr_user:
        return False
    final_grades = ""
    grade_changed = False
    for c in grades:
        if c.grade >= 0.0:
            if c.grade >= 100.0:
                grade_string = "{:.1f}% [{}] {}-- {}".format(c.grade, c.letter, (' ' if len(c.letter) is 1 else ''), c.name)
            else:
                grade_string = "{:.2f}% [{}] {}-- {}".format(c.grade, c.letter, (' ' if len(c.letter) is 1 else ''), c.name)
            diff = False
            if inDatabase:
                diff = c.diff_grade()
            if diff:
                grade_changed = True
                change_word = ('up' if diff > 0.0 else 'down')
                final_grades += grade_string + " [" + change_word + " " + str(abs(diff)) + "% from " + str(c.grade - diff) + "%]\n"
            elif showAll or c.new_assignments:
                final_grades += grade_string + "\n"
            if c.new_assignments:
                grade_changed = True
                for a in c.new_assignments:
                    final_grades += "{}: ({}/{}) [{}%]\n".format(a['assignment_name'], a['score'], a['total'], a['percent'])
                final_grades += "\n"
    if grade_changed:
        print("A grade changed")
    else:
        # if no grades changed, don't put spaces -- will only matter if manual testing
        final_grades = final_grades.replace("\n\n", "\n")

    return [grade_changed, final_grades.strip()]

def send_grade_email(email, isPhone, message):
    print("Sending grade email to {}".format(email))
    utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], email, '' if isPhone else 'Grade Alert', message)

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
        elif options.database:
            try:
                data = json.loads(options.database)
                if all (k in data for k in ("table", "method", "name", "type")):
                    if data['method'] == 'add_column':
                        sqlc.execute("ALTER TABLE '{}' ADD '{}' '{}'".format(data['table'], data['name'], data['type']))
                        conn.commit()
                    else:
                        print("Unrecognized method '{}'".format(data['method']))
                else:
                    print("Please provide table, method, name, and type")
            except KeyboardInterrupt:
                sys.exit()
            except Exception:
                full = traceback.format_exc()
                logging.warning("Exception: %s" % full)
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
        elif options.remove or options.exists:
            student_id = options.remove or options.exists
            if not User.exists(student_id):
                if options.remove:
                    print("Could not find user with student_id '{}'".format(student_id))
                elif options.exists:
                    print("0")
            else:
                if options.remove:
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
                if ':' in options.go:
                    student_id = options.go.split(':')[0]
                else:
                    student_id = options.go
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

    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | Main try failed", "{}".format(full))

def do_task(user, inDatabase):
    try:
        try_count = 3
        print("Logging in {}...".format(user))
        if not login(user, inDatabase):
            print("Log in failed, probably wrong credentials")
            if try_count > 0:
                try_count -= 1
                do_task(user, inDatabase)
                return
            if not dont_send_failed_login_email:
                send_admin_email("GN | Login failed", "{}".format(user))
            else:
                dont_send_failed_login_email = False
            return
        
        print("Grabbing grades of schedule from semester...")
        user.create_table_if_not_exists()
        grades = get_all_grades()
        if grades:
            # Print before saving to show changes
            # array: [ grade_changed, string ]
            # if 'not user.phone_email', send full text, if user.phone_email exists, use short
            email_to_use = (user.phone_email or user.email) if user.premium == 1 else user.email
            final_grades = get_grade_string(grades, inDatabase, email_to_use != user.phone_email or options.go)
            if final_grades:
                
                print("Got them")
                if inDatabase:
                    user.save_grades_to_database(grades)
                
                # If grade changed and no send email is false, send email
                if options.go:
                    should_send = options.go.split(':')[1] == '1' if ':' in options.go else True
                else:
                    should_send = (user.email and not inDatabase) or (inDatabase and (options.loud or (final_grades[0] and not options.quiet)))
                if should_send:
                    send_grade_email(email_to_use, email_to_use == user.phone_email, final_grades[1])

                dev_print(final_grades[1])
            else:
                print("Did not get grade_string")
                send_admin_email("GN | not grade_string", "{}\n\n{}".format(user, final_grades))
        else:
            print("Did not get grades")
            send_admin_email("GN | not grades", "{}\n\n{}".format(user, grades))

        logout()
    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        print("Doing task failed, probably login information failed?")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | do_task try failed", "{}\n\n{}".format(user, full))

if __name__ == '__main__':
    main()
