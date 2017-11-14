#!/usr/bin/env python

import time
import yaml
import json
import cookielib
import mechanize
import os
import string
import sys
import re
import mysql.connector
import mysql.connector.pooling
import traceback
import logging
import time
import getpass
import utils
import re
import threading
import math

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

class UserThread(threading.Thread):
    def __init__(self, user, inDatabase):
        threading.Thread.__init__(self)
        self.user = user
        self.inDatabase = inDatabase
    def run(self):
        do_task(self.user, self.inDatabase)

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
    if DEV_MODE or options.go:
        print(string)

DIRNAME = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_NAME = DIRNAME+"/config.yml"
cfg = {}

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

dont_send_failed_login_email = False

NON_DECIMAL = re.compile(r'[^\d.]+')

# THE DEFAULT RUN TO SCRAPE ALL IS NO OPTIONS, JUST THE SALT
# THE REST OF THESE OPTIONS IS EITHER FOR THE WEB PORTAL SIGN UP OR MY MANIPULATION OF THE DATABASE OR TESTING
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
parser.add_option('-z', '--salt', action='store', dest='z', help='Encryption salt')
# Example argument: '{"username": "STUDENT_ID_HERE", "password": "PASSWORD_HERE"}'
parser.add_option('-i', '--infinitecampus', action='store', dest='infinitecampus', metavar='USER_DICTIONARY', help='Check validity of infinite campus credentials')
# Example argument: '{"table": "TABLE_HERE", "method": "add_column", "name": "NAME_HERE", "type": "TYPE_HERE"}'
parser.add_option('-d', '--database', action='store', dest='database', metavar='DICTIONARY', help='Modify database')
parser.add_option('-j', '--json', action='store_true', dest='json', help='Output json')
parser.add_option('-t', '--transfer', action='store', dest='transfer', metavar='DICTIONARY', help='Transfer encryptions and users')

(options, args) = parser.parse_args()

def encrypted(string, salt=options.z):
    return hexlify(AESCipher(salt).encrypt(string))

def decrypted(string, salt=options.z):
    return AESCipher(salt).decrypt(unhexlify(string))

class Course:
    """an object for an individual class, contains a grade and class name"""
    def __init__(self, name, grade, letter, last_assignment, user):
        self.grade = grade
        self.name = name
        self.letter = letter
        self.last_assignment = last_assignment
        self.user = user

    @classmethod
    def course_from_name(self, user, name, pool):
        course_row = pool.execute("SELECT * FROM {} WHERE name = '{}'".format(user.get_table_name(), name), one=True)
        if course_row:
            try:
                last_assignment = json.loads(course_row.get('last_assignment', "{{}}"))
            except:
                last_assignment = {}
            return Course(course_row['name'], float(course_row['grade']), course_row['letter'], last_assignment, user)
        else:
            return False
    
    def save(self, pool):
        # replace single quote with two single quotes for sql entry
        pool.execute("REPLACE INTO {} VALUES ('{}', '{}', '{}', '{}')".format(self.user.get_table_name(), self.name, self.grade, self.letter, json.dumps(self.last_assignment).replace("'","''").replace('"', '\\"')), commit=True)

    def diff_grade(self, pool):
        """returns the difference between the current class grade
        and the last one
        """
        course_row = pool.execute("SELECT * FROM {} WHERE name = '{}'".format(self.user.get_table_name(), self.name), one=True)
        # Set prev grade to own grade so no difference if grade didn't exist
        prev_grade = (course_row['grade'] if course_row and 'grade' in course_row else self.grade)
        if prev_grade < 0.0:
            return False
        return float(self.grade) - float(prev_grade)

class User:
    # Gets list of all users in database
    @classmethod
    def get_all_users(self, where_clause, pool):
        User.setup_accounts_table(pool)
        user_rows = pool.execute("SELECT * FROM {}.accounts{}".format(cfg['mysql']['db'], " {}".format(where_clause) if where_clause else ''))
        users = []
        for user_row in user_rows:
            users.append(User.from_dict(user_row))
        return users
    
    @classmethod
    def setup_accounts_table(self, pool):
        pool.execute("CREATE TABLE IF NOT EXISTS {}.accounts (username VARCHAR(50), name VARCHAR(50), password TEXT, enabled INTEGER, student_id VARCHAR(8), recipients TEXT, UNIQUE KEY (student_id)) CHARSET=utf8;".format(cfg['mysql']['db']), commit=True)

    @classmethod
    def from_student_id(self, student_id, pool):
        User.setup_accounts_table(pool)
        user_row = pool.execute("SELECT * FROM {}.accounts WHERE student_id = '{}'".format(cfg['mysql']['db'], student_id), one=True)
        if not user_row:
            return None
        else:
            return User.from_dict(user_row)
    
    @classmethod
    def from_dict(self, row):
        user = self()
        user.username = row['username']
        user.name = row.get('name', 'Unknown Name')
        user.email = row.get('email')
        user.password = row['password']
        user.enabled = row.get('enabled', 1)
        user.student_id = row['student_id']
        user.recipients = json.loads(row.get('recipients', '[]') or '[]')
        return user
    
    @classmethod
    def exists(self, student_id, pool):
        User.setup_accounts_table(pool)
        rows = pool.execute("SELECT COUNT(*) FROM {}.accounts WHERE student_id = '{}'".format(cfg['mysql']['db'], student_id), one=True)['COUNT(*)']
        return rows > 0
    
    def get_table_name(self):
        return "{}.user_{}".format(cfg['mysql']['db'], self.student_id)
    
    def create_account(self, pool):
        User.setup_accounts_table(pool)
        pool.execute("INSERT INTO {}.accounts VALUES ('{}', '{}', '{}', '{}', '{}', '{}')".format(cfg['mysql']['db'], self.username, self.name, self.password, 1, self.student_id, json.dumps(self.recipients)), commit=True)
        self.create_table_if_not_exists(pool)
    
    @classmethod
    def remove_account(self, student_id, pool):
        user = User.from_student_id(student_id, pool)
        pool.execute("DELETE FROM {}.accounts WHERE student_id = '{}'".format(cfg['mysql']['db'], student_id), commit=True)
        return user
    
    @classmethod
    def valid_password(self, student_id, password, pool):
        user = User.from_student_id(student_id, pool)
        if user:
            password_row = decrypted(user.password)
            return user if password == password_row else False
        else:
            return False
    
    def create_table_if_not_exists(self, pool):
        pool.execute("CREATE TABLE IF NOT EXISTS {} (name VARCHAR(60), grade FLOAT(6,3), letter VARCHAR(2), last_assignment TEXT, UNIQUE KEY (name)) CHARSET=utf8;".format(self.get_table_name()), commit=True)
    
    def update(self, key, value, pool):
        User.setup_accounts_table(pool)
        pool.execute("UPDATE {}.accounts SET {} = '{}' WHERE student_id = '{}'".format(cfg['mysql']['db'], key, value, self.student_id), commit=True)
        setattr(self, key, value)

    def save_grades_to_database(self, grades, pool):
        for course in grades:
            course.save(pool)

    def __str__(self):
        return "{} ({} -- {}) [{}]".format(self.name, self.username, self.student_id, self.enabled)
    
    def json(self):
        return {'enabled': self.enabled, 'student_id': self.student_id, 'username': self.username, 'name': self.name, 'recipients': self.recipients}

class MySQLPool(object):
    """
    create a pool when connect mysql, which will decrease the time spent in 
    request connection, create connection and close connection.
    """
    def __init__(self, dbconfig, pool_name="mypool",
                pool_size=32):
        self.dbconfig = dbconfig
        self.pool = self.create_pool(pool_name=pool_name, pool_size=pool_size)

    def create_pool(self, pool_name="mypool", pool_size=32):
        """
        Create a connection pool, after created, the request of connecting 
        MySQL could get a connection from this pool instead of request to 
        create a connection.
        :param pool_name: the name of pool, default is "mypool"
        :param pool_size: the size of pool, default is 3
        :return: connection pool
        """
        pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name=pool_name,
            pool_size=pool_size,
            pool_reset_session=True,
            **self.dbconfig)
        return pool

    def close(self, conn, cursor):
        """
        A method used to close connection of mysql.
        :param conn: 
        :param cursor: 
        :return: 
        """
        cursor.close()
        conn.close()

    def execute(self, sql, one=False, args=None, commit=False):
        """
        Execute a sql, it could be with args and with out args. The usage is 
        similar with execute() function in module pymysql.
        :param sql: sql clause
        :param args: args need by sql clause
        :param commit: whether to commit
        :return: if commit, return None, else, return result
        """
        # get connection form connection pool instead of create one.
        conn = self.pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        if args:
            cursor.execute(sql, args)
        else:
            cursor.execute(sql)
        if commit is True:
            conn.commit()
            self.close(conn, cursor)
            return None
        else:
            if one is True:
                res = cursor.fetchone()
            else:
                res = cursor.fetchall()
            self.close(conn, cursor)
            return res

pool = None

def setup():
    """general setup commands"""
    
    # Setup config
    global cfg
    with open(CONFIG_FILE_NAME, 'r') as cfgfile:
        cfg = yaml.load(cfgfile)
    
    dbconfig = {
        "host": cfg['mysql']['host'],
        "port": cfg['mysql']['port'],
        "user": cfg['mysql']['user'],
        "passwd": cfg['mysql']['passwd'],
        "db": cfg['mysql']['db']
    }
    global pool
    pool = MySQLPool(dbconfig)

def get_browser():
    br = mechanize.Browser()
    
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

    return br

def get_base_url():
    """returns the site's base url, taken from the login page url"""
    return cfg['login_url'].split("/campus")[0] + '/campus/'

def get_portal_data(curr_user, br):
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

def get_page_url(gradesPage, dom, curr_user):
    """returns the url of the schedule page"""
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

    nodes = node.getElementsByTagName('Calendar')
    if len(nodes) < 1:
        return False
    node = nodes[0]
    school_id = node.getAttribute('schoolID')

    nodes = node.getElementsByTagName('ScheduleStructure')
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

def get_all_grades(curr_user, pool):
    soup = curr_user.grade_page_data

    courses = []

    in_progress_grades = soup.findAll(name='td', attrs={'class':'inProgressGrade'})
    for in_prog_grade in in_progress_grades:
        contents = in_prog_grade.contents
        if len(contents) == 2:
            grade = float(NON_DECIMAL.sub('', contents[0]))
            letter = contents[1].getText().strip()
            name = in_prog_grade.parent.parent.find('tr').find('td', attrs={'class': 'gradesLink'}).find('a').find('b').getText().strip() # td.inProgressGrade < tr < tbody > tr.find(td.gradesLink) > a > b
            # manipulate name
            name = name.replace('&amp;','&').split(' ')
            name.pop(0)
            name = " ".join(name)
            # get assignments
            # $('div#recentAssignments table.portalTable tbody tr')
            assignments = {}
            if True:
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

                    assignment_name = cont[7].getText().strip().replace('&amp;','&')
                    score = NON_DECIMAL.sub('', cont[9].getText().strip())
                    total = NON_DECIMAL.sub('', cont[11].getText().strip())
                    percent = NON_DECIMAL.sub('', cont[13].getText().strip())
                    
                    assignments[course_name].append({ 'assignment_name': assignment_name, 'score': score, 'total': total, 'percent': percent })

                    # print("{} -- {} [{}/{}] ({})".format(course_name, assignment_name, score, total, percent))
            
            course = Course.course_from_name(curr_user, name, pool)

            if not course:
                course = Course(name, float(grade), letter, {}, curr_user)
            
            course.grade = grade
            course.letter = letter
            
            if name in assignments:
                course_assignments = assignments[name]
                new_assignments = []
                if course.last_assignment and course.last_assignment in course_assignments:
                    index_of_last = course_assignments.index(course.last_assignment)
                    new_assignments = course_assignments[:index_of_last]
                else:
                    # specific assignment grade changed or doesn't exist, search for just name if couldn't find whole thing
                    course_assignments_array = dict((a['assignment_name'], course_assignments.index(a)) for a in course_assignments)
                    if course.last_assignment and course.last_assignment['assignment_name'] in course_assignments_array:
                        index_of_last = course_assignments_array[course.last_assignment['assignment_name']]
                        index_with_prev_last = index_of_last + 1
                        new_assignments = course_assignments[:index_with_prev_last]
                    else:
                        # specific assignment grade name not found, take all occurrences
                        new_assignments = course_assignments
                
                course.last_assignment = course_assignments[0]
                course.new_assignments = new_assignments

            else:
                course.new_assignments = []

            # add course
            courses.append(course)
    return courses

def login(user, shouldDecrypt, br):
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

        # if not error_msg and not status_error:
        if iframe:

            dom = get_portal_data(user, br)
            if dom:
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
                    # schedule_page_data = None
                    # for idx in range(3):
                    #     schedule_page_data = br.open(get_page_url(False))
                    #     if schedule_page_data:
                    #         schedule_page_data = BeautifulSoup(schedule_page_data)
                    #         if schedule_page_data:
                    #             break
                    grade_page_data = None
                    for idx in range(3):
                        grade_page_data = br.open(get_page_url(True, dom, user))
                        if grade_page_data:
                            grade_page_data = BeautifulSoup(grade_page_data)
                            if grade_page_data:
                                user.grade_page_data = grade_page_data
                                break

                    return not not grade_page_data

        dont_send_failed_login_email = False
        
    except KeyboardInterrupt:
        sys.exit()
    except (mechanize.HTTPError, mechanize.URLError) as e:
        print("Could not connect to Infinite Campus' servers. Please try again later when it is back up so your credentials can be verified.")
        dont_send_failed_login_email = True
    except Exception:
        print("[{}] Logging in failed".format(user))
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | login try failed", "{}\n\n{}".format(user, full))
    
    return False

def logout(br):
    """Logs out of Infinite Campus
    """
    try:
        br.open(get_base_url() + 'logoff.jsp')
    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        # print("Logging out failed")
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        # send_admin_email("GN | logout try failed", "{}\n\n{}".format(curr_user, full))

# returns array where index 0 element is grade_changed (boolean) and index 1 element is grade string
def get_grade_string(grades, inDatabase, showAll, curr_user, pool):
    """Extracts the grade_string"""
    final_grades = ""
    grade_changed = False
    for c in grades:
        if c.grade >= 0.0:
            diff = False
            if inDatabase:
                diff = c.diff_grade(pool)
            if c.new_assignments and len(final_grades) > 0:
                final_grades += "\n"
            if showAll or c.new_assignments or diff:
                final_grades += "{}% [{}]: {}".format(c.grade, c.letter, c.name)
            if diff:
                grade_changed = True
                change_word = ('up' if diff > 0.0 else 'down')
                final_grades += " [" + change_word + " " + str(abs(diff)) + "% from " + str(c.grade - diff) + "%]\n"
            else:
                final_grades += "\n"
            if c.new_assignments:
                grade_changed = True
                for a in c.new_assignments:
                    final_grades += "{}: ({}/{}) [{}%]\n".format(a['assignment_name'], a['score'], a['total'], a['percent'])
                final_grades += "\n"
    # if grade_changed:
        # print("A grade changed")
    else:
        # if no grades changed, don't put spaces -- will only matter if manual testing
        final_grades = final_grades.replace("\n\n", "\n")

    return [grade_changed, final_grades.strip()]

def send_grade_email(email, isPhone, message):
    # print("Sending grade email to {}".format(email))
    utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], email, '' if isPhone else 'Grade Alert', message)

def send_admin_email(subject, message):
    if not DEV_MODE:
        utils.send_email(cfg['smtp_address'], cfg['smtp_username'], cfg['smtp_password'], 'noahsaso@gmail.com', subject, message)

def main():
    # Run every 10 minutes with a cron job (*/10 * * * * /path/to/grades.py)
    try:

        setup()
        
        # move one encryption to another for specified users
        if options.transfer:

            data = json.loads(options.transfer)

            for user in User.get_all_users('' if 'student_ids' not in data else "WHERE student_id IN ({})".format(",".join(data['student_ids'])), pool):
                user.update('password', encrypted(decrypted(user.password, salt=data['salt_from']), salt=data['salt_to']), pool)

            return

        br = get_browser()

        if options.database:
            try:
                data = json.loads(options.database)
                if all (k in data for k in ("table", "method", "name", "type")):
                    if data['method'] == 'add_column':
                        pool.execute("ALTER TABLE {}.{} ADD '{}' '{}'".format(cfg['mysql']['db'], data['table'], data['name'], data['type']), commit=True)
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
                if User.exists(student_id, pool):
                    # USER EXISTS
                    if options.valid:
                        if not options.z:
                            print("Please include the encryption salt")
                            return
                        if "password" not in user_data:
                            print("Please provide the password")
                            return
                        user = User.valid_password(student_id, user_data['password'], pool)
                        if user:
                            print(json.dumps(user.json()))
                        else:
                            print("0")
                    elif options.modify:
                        if all (k in user_data for k in ("key", "value")):
                            user = User.from_student_id(student_id, pool)
                            new_value = user_data['value']
                            if user_data['key'] == 'password':
                                if options.z:
                                    new_value = encrypted(new_value)
                                else:
                                    print("Please include the encryption salt")
                                    return
                            user.update(user_data['key'], new_value, pool)
                            send_admin_email("GN | User Updated", "Updated {} for {}".format(user_data['key'], user))
                            print("Updated {} for {}".format(user_data['key'], user))
                        else:
                            print("Please provide student_id, key, and value")
                else:
                    # USER DOES NOT EXIST
                    if options.valid:
                        print("0")
                    elif options.modify:
                        if student_id == 'all':
                            if all (k in user_data for k in ("key", "value")):
                                for user in User.get_all_users('', pool):
                                    new_value = user_data['value']
                                    if user_data['key'] == 'password':
                                        if options.z:
                                            new_value = encrypted(new_value)
                                        else:
                                            print("Please include the encryption salt")
                                            return
                                    user.update(user_data['key'], new_value, pool)
                                    print("Updated {} for {}".format(user_data['key'], user))
                            else:
                                print("Please provide student_id, key, and value")
                        else:
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
                        print("1" if login(user, False, br) else "0")
                    else:
                        print("Please provide a username, password, and student_id")
                else:
                    if User.exists(student_id, pool):
                        if options.add:
                            print("A user with student_id '{}' already exists. Please use the -e flag instead".format(student_id))
                    elif options.add:
                        if all (k in user_data for k in ("name", "password")):
                            # If forgot encryption salt, tell them
                            if not options.z:
                                print("Please include the encryption salt")
                            else:
                                user = User.from_dict(user_data)
                                user.password = encrypted(user.password)
                                user.create_account(pool)
                                send_admin_email("GN | User Created", "Created {}".format(user))
                                print("Added {}".format(user))
                        else:
                            print("Please provide name, username, student_id, and password")
        # argument is student_id
        elif options.remove or options.exists:
            student_id = options.remove or options.exists
            if not User.exists(student_id, pool):
                if options.remove:
                    print("Could not find user with student_id '{}'".format(student_id))
                elif options.exists:
                    print("0")
            else:
                if options.remove:
                    user = User.remove_account(student_id, pool)
                    send_admin_email("GN | User Removed", "Removed {}".format(user))
                    print("Removed {}".format(user))
                elif options.exists:
                    print("1")
        elif options.list:
            disabled_users = []
            enabled_users = []
            if options.json:
                for user in User.get_all_users('', pool):
                    if user.enabled == 1:
                        enabled_users.append(user.json())
                    else:
                        disabled_users.append(user.json())
                final_string = json.dumps({
                    'disabled': disabled_users,
                    'enabled': enabled_users
                });
            else:
                for user in User.get_all_users('', pool):
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
                if User.exists(student_id, pool):
                    do_task(User.from_student_id(student_id, pool), True)
                else:
                    print("Could not find user with student_id {}".format(student_id))
        elif options.createall:
            for user in User.get_all_users('', pool):
                user.create_table_if_not_exists(pool)
        else:
            # If not checking single
            if not options.check:
                # If forgot encryption salt, tell them
                if not options.z:
                    print("Please include the encryption salt")
                else:
                    # Get users
                    start_time_total = time.time()
                    all_users = User.get_all_users('WHERE enabled = 1', pool)
                    all_users_count = len(all_users)
                    how_many = int(math.ceil(all_users_count/32.0))
                    for i in range(how_many):
                        # take each chunk of 32 students so mysql pool is not exhausted
                        users = all_users[(i*32):((i*32+32) if (i*32+32) < all_users_count else all_users_count)]
                        threads = []
                        for user in users:
                            t = UserThread(user, True)
                            t.start()
                            threads.append(t)
                        for t in threads:
                            t.join()
                            # do_task(user, True)
                    final_time = time.time()
                    print("----- Total Time: %.5f seconds, Average Time per User: %.5f seconds -----" % ((final_time - start_time_total), (final_time - start_time_total)/all_users_count))
                    # print("----- Average Time per User: %s seconds -----" % ((time.time() - start_time_total)/count_total))

            # Else if specified check user
            else:
                do_task(User.from_dict(json.loads(options.check)), False)

    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | Main try failed", "{}".format(full))

def do_task(user, inDatabase):
    try:
        br = get_browser()
        # start_time = time.time()
        print("[{}] Logging in...".format(user))
        global dont_send_failed_login_email
        if not login(user, inDatabase, br):
            print("[{}] Log in failed".format(user))
            if dont_send_failed_login_email:
                # send_admin_email("GN | Login failed", "{}".format(user))
                # print('didnt send admin email but login failed')
            # else:
                dont_send_failed_login_email = False
            return
        
        # print("Grabbing grades of schedule from semester...")
        user.create_table_if_not_exists(pool)
        grades = get_all_grades(user, pool)
        if grades:
            # Print before saving to show changes
            # array: [ grade_changed, string ]
            final_grades = get_grade_string(grades, inDatabase, options.go, user, pool)
            if final_grades:
                
                # print("Got them")
                if inDatabase:
                    user.save_grades_to_database(grades, pool)
                
                # If grade changed and no send email is false, send email
                if options.go:
                    should_send = options.go.split(':')[1] == '1' if ':' in options.go else True
                else:
                    should_send = (user.email and not inDatabase) or (inDatabase and (options.loud or (final_grades[0] and not options.quiet)))
                if should_send:
                    if inDatabase:
                        for recipient in user.recipients:
                            if recipient['enabled'] == 1:
                                send_grade_email(recipient['address'], recipient['type'] == 'phone', final_grades[1])
                    else:
                        send_grade_email(user.email, False, final_grades[1])
                    print("[{}] Finished, sent".format(user))
                else:
                    print("[{}] Finished, not sending (grades changed: {})".format(user, final_grades[0]))

            else:
                print("[{}] Finished, did not get grade string".format(user))
                send_admin_email("GN | not grade_string", "{}\n\n{}".format(user, final_grades))
        else:
            print("[{}] Finished, did not get grades".format(user))
            send_admin_email("GN | not grades", "{}\n\n{}\n\n{}".format(user, grades, user.grade_page_data))

        logout(br)

        # print("----- Took %s seconds -----" % (time.time() - start_time))
    except KeyboardInterrupt:
        sys.exit()
    except Exception:
        print("[{}] Finished, doing task failed, probably login information failed?".format(user))
        full = traceback.format_exc()
        logging.warning("Exception: %s" % full)
        send_admin_email("GN | do_task try failed", "{}\n\n{}".format(user, full))

if __name__ == '__main__':
    main()
