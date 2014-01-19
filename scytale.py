#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3 as sql
import argparse
import sys

from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import getpass

BLOCK_SIZE = 32
SUPP = ' ' # used to pad password to 16 bits
TABLE_NAME="scytale_data"
global conn
conn = None

def sql_connect(fname):
    """
    connect to sqlite3 database file
    
    return: cursor - sqlite cursor object
    fname: (string) sqlite database file name
    """
    
    # check if database exist
    try:
        open(fname)
    except IOError:
        print('Database file does not exist. Use -c to create it.')
        sys.exit(1)
    try:
        global conn 
        conn = sql.connect(fname)
        cursor = conn.cursor()
        
        return cursor
    
    except sql.Error as e:
        print "Can't connect to database file: %s" % e.args[0]
        sql_close()
        sys.exit(1)

def sql_create(fname):
    """
    create new database file and table structure
    
    return: cursor - sqlite cursor object
    fname: (string) sqlite database file name
    """
    try:
        global conn
        conn = sql.connect(fname)
        cursor = conn.cursor()
    
        cursor.execute('CREATE TABLE '+TABLE_NAME+' (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, name VARCHAR(128), pass VARCHAR(256), type VARCHAR(32), keywords VARCHAR(256))')
        conn.commit()
        return cursor

    except sql.Error as e:
        print "Faild to create database: %s" % e.args[0]
        sql_close()
        sys.exit(1)
    
def sql_close():
    """
    close sqllite connection, commiting first
    
    conn: connection object
    """
    try:
        global conn
        if conn:
            conn.commit()
            conn.close()
    except sql.Error as e:
        print "Faild to close connection: %s" % e.args[0]

def sql_add(cursor,name,enc_pass, rtype, keywords):
    """
    insert new record to sqlite database
    
    cursor: sqlite cursor object
    name: (string) name of password object ie. bank account ;)
    enc_pass: (string) encrypted password
    rtype: (string) record type ie. work, home, own etc
    keywords: (string) words that can help find record
    """
    
    try:
        cursor.execute('INSERT INTO '+TABLE_NAME+' (name,pass,type,keywords) VALUES(?,?,?,?)',(name,enc_pass, rtype, keywords.replace(","," ")))
        global conn
        conn.commit()
    except sql.Error as e:
        print "Faild to add data: %s" % e.args[0]
        sql_close()
        sys.exit(1)
        
def search(cursor,keywords):
    """
    search for password object based on provided keywords
    
    return: list of tuples (rows)
            
    cursor: sqlite cursor object
    keywords: (string) list of keywords divided by coma
    """
    klist=keywords.split(',')
    
    if len(klist) == 0:
        query='SELECT * from '+TABLE_NAME
    else:
    	query="SELECT * from "+TABLE_NAME+" where '' "
    	for key in klist:
    	    query=query+" OR name LIKE('%"+key+"%') OR keywords LIKE('%"+key+"%')"   
    try:
        cursor.execute(query)
        rows=cursor.fetchall()
        return rows    
    except sql.Error as e:
        print "Faild to fetch data: %s" % e.args[0]
        sql_close()
        sys.exit(1)
        
def sql_delete(cursor,rowID):
    """
    delete rows witch provided id
    
    rowID: row ID number
    """
    try:
        cursor.execute("DELETE FROM "+TABLE_NAME+" where id=?",[rowID])
        global conn
        conn.commit()
    except sql.Error as e:
        print "Faild to delete data: %s" % e.args[0]
        sql_close()
        sys.exit(1)

# Links used to write next two functions:
# * https://www.dlitz.net/software/pycrypto/api/current/
# * http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
# * https://gist.github.com/sekondus/4322469


def encrypt(key, password):
    """
    encrypt password
    
    return: (string) initialization vector (size of  BLOCK_SIZE)+encoded password
    key: (string) secret key phrase used to encrypt password
    password: (string) password to encrypt
    """
    
    key32 = hashlib.sha256(key).digest() # make a key 32 byte long
    password32 = password + (BLOCK_SIZE - len(password) % BLOCK_SIZE) * SUPP # password need to have 32 bytes
    iv = Random.new().read(AES.block_size) # generate random initialization vector
    cipher = AES.new(key32, AES.MODE_CBC, iv)
    
    return base64.b64encode(iv + cipher.encrypt(password32)) # return binary string as a text string (http://docs.python.org/2/library/base64.html)

def decrypt(key, enc):
    """
    decrypt encrypted password
    
    return: (string) encrypted password
    key: (string) secret key pass pharase
    enc: (string)iv+encrypted password
    """
    enc=base64.b64decode(enc) # decode text string to binary string
    
    key32 = hashlib.sha256(key).digest() # key is always 32 bytes long
    iv=enc[0:AES.block_size] # get initialization vector from encrypted string
    encpass=enc[AES.block_size:] # get encrypted password
    
    decryptor = AES.new(key32, AES.MODE_CBC, iv)
    
    return decryptor.decrypt(encpass).strip(' ')

def get_password(pwType):
	"""
        if no password has been defined using -p or -m obtion it will ask for new password without echoing it, if -m or -p were defined it will clear last line of command line history
	
	pwType: (string)password type (master,object)
	return: (string) password
	"""
	pwTypeS=('master','object')
	
	if(pwType not in pwTypeS):
	    print "Wrong password type, allowed types: "+str(pwTypeS)
	    sys.exit(1)
	if (pwType == 'master'):
	    if args.mpasswd:
	        # clear history
	        return args.mpasswd
	    prompt="new object password"
	if (pwType == 'object'):
	    if args.opasswd:
	        # clear history
	        return args.opasswd
	    prompt="master password"
	    
	correct=False
	
	while(not correct):

		password1=getpass.getpass("Type "+prompt+": ")
		password2=getpass.getpass("Retype"+prompt+": ")
		
		if(password1 == password2):
			correct=True
			return password1
		else:
			print("Passwords does not match")

def arg_parser():
    parser = argparse.ArgumentParser(prog='SCYTALE')
    req_group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument("dbfile", help="sqlite3 database file")
    parser.add_argument("-k","--keywords", help="search criteria divided by coma")
    parser.add_argument("-n","--name", help="password object name")
    parser.add_argument("-t","--type", help="type of password object, default='default'") # use od that in TODO list
    parser.add_argument("-m","--mpasswd",help="master password")
    parser.add_argument("-o","--opasswd",help="object password")
    parser.add_argument("-f","--force", action="store_true", help="force 'y' answer to all questions")
    req_group.add_argument("-g","--get", action="store_true",help="display password object(s), if no  -k option it will display all password objects")
    req_group.add_argument("-a","--add", action="store_true", help="add new password object, require -n, using -k is prefered (if not specified will be equal to -n)")
    req_group.add_argument("-d","--delete", action="store_true", help="delete password object, use with -k or -n or both")
    req_group.add_argument("-c","--create", action="store_true", help="create new, empty database file with a given name")
	
    return parser.parse_args()
                
args = arg_parser()

# FORCE option - to be used later or never
if args.force:
    global FORCE
    FORCE = True

# CREATE
if args.create:
    cursor=sql_create(args.dbfile)
    print "Data structures created in "+args.dbfile

# ADD
if args.add:
    if args.name == None:
        print("You need to add -n NAME")
	sys.exit(1)
    else:
        cursor=sql_connect(args.dbfile)

        if args.keywords == None:
            args.keywords=args.name
        else:
            args.keywords+=(","+args.name) # always add password object name to keyword list

        if args.type == None:
            args.type = 'default'
        
        opasswd=get_password('object')        
        mpasswd=get_password('master')
        
        sql_add(cursor,args.name,encrypt(mpasswd,opasswd),args.type, args.keywords) 

# DELETE - TODO
if args.delete:
    if args.keywords == None :
        print("You need to add -k KEYWORDS")
        sys.exit(1)
    else:
        cursor=sql_connect(args.dbfile)
        result=search(cursor,args.keywords)
        if len(result) == 0:
            print("No record for DELETE found")
            sys.exit(0)
            
        resIDlist=[]
        print "id\tname\t\ttype\t\tkeywords\n"
        for rid,name,encpass,pwdtype,keywords in result:
            resIDlist.append(str(rid))
            print str(rid)+"\t"+name+"\t\t"+pwdtype+"\t\t"+keywords
        correct=False
        
        
        ans=raw_input("Type id list divided with coma or 'a' to delete all above objects: ")
        if ans == 'a':
            for rid in resIDlist:
                sql_delete(cursor,rid)
                correct=True    
        else:
            for rid in ans.split(","):
                if rid not in resIDlist:
                    print "Id '"+rid+"' not in the result list, skipping"
                else:
                    sql_delete(cursor,rid)
                            
# GET	
if args.get:
    cursor=sql_connect(args.dbfile)
    password=getpass.getpass()
    if args.keywords == None:
        for rid,name,encpass,pwdtype,keywords in search(cursor,""):
            print name,
            print "\t\t"+decrypt(password,encpass),
            print "\t\t"+keywords
    else:
        for rid,name,encpass,pwdtype,keywords in search(cursor,args.keywords):
            print name,
            print "\t\t"+decrypt(password,encpass),
            print "\t\t"+keywords