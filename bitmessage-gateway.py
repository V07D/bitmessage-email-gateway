#!/usr/bin/python

## imports
import os
import re
import time
import time
import argparse
import logging
import sys
import xmlrpclib
import json
import smtplib
import base64
import email
from email.parser import Parser
from email.header import decode_header
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText


## globals
folder = '/home/bitmessage/MailDir/new/'
log_filename = 'logs/bitmessage-gateway.log'
logging.basicConfig(filename=log_filename,level=logging.INFO)
process_interval = 10
api = {
	'conn' : '',
	'username' : 'bmapi',
	'password' : 'VI4164OGqTqRkIt',
	'host' : '127.0.0.1',
	'port' : '8442'

}


## connect to Bitmessage API
def api_connect(module):

	global api

	api['conn'] = xmlrpclib.ServerProxy('http://' + api['username'] + ':' + api['password'] + '@' + api['host'] + ':' + api['port'] + '/')
	response = api['conn'].add(2,2)
	if not response == 4:
		logging.info('Could not connect to Bitmessage API: ' + response)
		return False
	else:
		logging.info(module + " module loaded Bitmessage API and started")
		return True


## find inbound address list for sending bitmessages from external email addresses
def get_address_list():

	global api

	bm_addresses = json.loads(api['conn'].listAddresses())['addresses']
	address_list = {}
	for address in bm_addresses:
		address_list[address['label']] = address['address']
	return address_list


## find destonation addressbook for sending bitmessages
def get_addressbook():

	global api

	bm_addressbook = json.loads(api['conn'].listAddressBookEntries())['addresses']		
	addressbook = {}
	for address in bm_addressbook:
		addressbook[base64.b64decode(address['label'])] = address['address']	
	return addressbook


## read email from file
def read_email(k):

	global folder
	
	try:
		f = open(folder + k, 'r')
		message = f.read()
		return message
	except IOError:
		logging.info('Could not read email: ' + folder + k)
		return


## delete email from file
def delete_email(k):

	global folder

	try:
		os.remove(folder + k)
	except OSError:
		logging.info('Could not delete email: ' + folder + k)


## generate a bitmessage address for an incoming email sender
def generate_sender_address(email):

	global api

	time_start = time.time()
	address = api['conn'].createRandomAddress(base64.b64encode(email))
	time_stop = time.time()
	time_total = int(time_stop - time_start)

	logging.info('Generated sender address for ' + email + ' in ' + str(time_total) + ' seconds')
	return address


## send bitmessage
def send_bitmessage(bm_to_address, bm_from_address, bm_subject, bm_body, from_email, to_email):

	global api
	
	time_start = time.time()
	ackData = api['conn'].sendMessage(bm_to_address, bm_from_address, bm_subject, bm_body, 2)

	while not "msgsent" in api['conn'].getStatus(ackData):
		time.sleep(5)
		# print api['conn'].getStatus(ackData)
	time_stop = time.time()
	time_total = int(time_stop - time_start)

	logging.info('Sent bitmessage from ' + from_email + ' (' + bm_from_address + ')  to ' + to_email + ' (' + bm_to_address + ') in ' + str(time_total) + ' seconds')


## check for new bitmessages
def get_bitmessages():

	global api 
	return json.loads(api['conn'].getAllInboxMessages())['inboxMessages']


## delete bitmessage
def delete_bitmessage(msgid):

	global api
	api['conn'].trashMessage(msgid)


## send outbound email
def send_email(receiver, sender, subject, body, bm_id):

	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = receiver
	msg['Subject'] = subject
	msg.attach(MIMEText(body, 'plain'))
	server = smtplib.SMTP('localhost')
	server.set_debuglevel(1)
	text = msg.as_string()

	try:
		server.sendmail(sender, receiver, text)
   		logging.info('Sent email from ' + sender + ' to ' + receiver)
		delete_bitmessage(bm_id)
	except:
   		logging.info('Could not send email from ' + sender + ' to ' + receiver)
	
	server.quit()


## list known addresses
def list_addresses():

	## get all addresses 
	address_list = get_address_list()
	print "\n####################################\nExternal Address List\n####################################"
	for tmp_email in address_list:
		print tmp_email + "\t\t\t" + address_list[tmp_email]
	print ''

	addressbook = get_addressbook()	
	print "\n####################################\nInternal Address List\n####################################"
	for tmp_email in addressbook:
		print tmp_email + "\t\t\t" + addressbook[tmp_email]
	print ""


## delete address
def delete_address(address):

	## try to delete and don't worry about if it actually goes through
	global api
	api['conn'].deleteAddressBookEntry(address)
	api['conn'].deleteAddress(address)


## check for new bitmessages to process
def check_messages():


	## check if new messages are available
	messages = get_bitmessages()
	if not messages:
		return


	## get all addresses 
	address_list = get_address_list()
	addressbook = get_addressbook()	


	## loop through new messages
	for message in messages:


		## find message ID
		bm_id = message['msgid']


		## check if sender has an outbound email address, else purge
		bm_sender = ''
		for tmp_email, tmp_address in addressbook.iteritems():
			if tmp_address == message['fromAddress']:
				bm_sender = tmp_email
		if not bm_sender:
			logging.info('Purged bitmessage from non-registered user ' + bm_sender)
			delete_bitmessage(bm_id)
			continue


		## if receive address is bound to an email
		bm_receiver = ''
		bm_subject = ''
		if not message['toAddress'] == address_list['GoDark Sender Address']:
			for tmp_email, tmp_address in address_list.iteritems():
				if tmp_address == message['toAddress']:
					bm_receiver = tmp_email	
					bm_subject = base64.b64decode(message['subject'])


		## if sent to generic receiver address, build email address from subject
		else:
			bm_receiver = re.findall(r'[\w\.-]+@[\w\.-]+\.[\w]+', base64.b64decode(message['subject']))
			if len(bm_receiver) > 0:
				bm_receiver = bm_receiver[0]


		## if subject doesnt contain valid email, mark message as bad
		if not bm_receiver:
			logging.info('Received and purged message with unknown recipient (likely generic address and bad subject)')
			delete_bitmessage(bm_id)
			continue


		## handle removal of embedded BMG-FROM:: tag for replies
		bm_subject = bm_subject.replace('BMG-FROM::' + bm_receiver + ' | ', '');


		## get message contents
		bm_body = base64.b64decode(message['message'])	


		# ## print message details
		# print "\nReady to process message:"
		# print "\tFrom: " + bm_sender
		# print "\tTo:   " + bm_receiver
		# print "\tSub:  " + bm_subject
		# print "\tMsg:  " + bm_body


		## send message and delete bitmessage, bitches
		send_email(bm_receiver, bm_sender, bm_subject, bm_body, bm_id)


## check for new mail to process
def check_emails():

	## find new messages in folders
	global folder
	dir = os.listdir(folder)

	## no new mail
	if not dir:
		return

	## get all addresses 
	address_list = get_address_list()


	## iterate through new messages
	for k in dir:


		## read email from file
		msg_raw = read_email(k)
		if not msg_raw:
			logging.info('Could not open email file: ' + k)
			continue

		## extract header
		msg_headers = Parser().parsestr(msg_raw)


		## find email source and dest addresses
		msg_sender    = msg_headers["Return-path"]
		msg_sender    = re.findall(r'[\w\.-]+@[\w\.-]+.[\w]+', msg_sender)[0]
		msg_recipient = msg_headers["To"]


		## check if we have valid sender and recipient details
		if not msg_sender or not msg_recipient:
			logging.info('Malformed email detected and purged')
			delete_email(k)
			continue
        

		## check if we have a recipient address for the receiving email
		addressbook = get_addressbook()
		if not msg_recipient in addressbook:
			logging.info('Purged email for unknown user ' + msg_recipient)
			delete_email(k)
			continue


		## set bitmessage destination address
		bm_to_address = addressbook[msg_recipient]


		## check to see if we need to generate a sending address for the source email address
		if not msg_sender in address_list:
			bm_from_address = generate_sender_address(msg_sender)
			address_list[msg_sender] = bm_from_address
		else:
			bm_from_address = address_list[msg_sender]


		## find message subject
		msg_subject = decode_header(msg_headers['subject'])[0]
		if(msg_subject[1]):
			msg_subject = unicode(msg_subject[0], msg_subject[1])
		else:
			msg_subject = msg_subject[0]


		## find message body contents in plaintext
		msg_tmp = email.message_from_string(msg_raw)
		msg_body = ''
		for part in msg_tmp.walk():
				if part.get_content_type() == 'text/plain':
					msg_body = msg_body + part.get_payload() #


		## print message status
		# print "\nReady to send message:"
		# print "\tFrom:     " + msg_sender + " (" + bm_from_address + ")"
		# print "\tTo:       " + msg_recipient + " (" + bm_to_address + ")"
		# print "\tSubject:  " + msg_subject
		# print "\tMessage:  " + msg_body


		## send message to bitmessage address
		bm_subject = base64.b64encode('BMG-FROM::' + msg_sender + ' | ' + msg_subject)
		bm_body = base64.b64encode(msg_body)
		send_bitmessage(bm_to_address, bm_from_address, bm_subject, bm_body, msg_sender, msg_recipient)


		## remove email file
		delete_email(k)


## main                                     
parser = argparse.ArgumentParser(description='An email <-> bitmessage gateway.')
parser.add_argument('-e','--emails', help='Process email queue',required=False, action='store_true')
parser.add_argument('-m','--messages', help='Process bitmessage queue',required=False, action='store_true')
parser.add_argument('-l','--list', help='List known internal and external messages',required=False, action='store_true', default=True)
parser.add_argument('-d','--delete', help='Delete an address',required=False, default=False)

args = parser.parse_args()

## call correct function
if args.emails == True:
	if api_connect('Email') == False:
		sys.exit()
	while True:
		check_emails()
		time.sleep(process_interval)

elif args.messages == True:
	if api_connect('Bitessage') == False:
		sys.exit()
	while True:
		check_messages()
		time.sleep(process_interval)

elif args.delete:
	if api_connect('Address deleter') == False:
		sys.exit()
	delete_address(args.delete)	

else:
	if api_connect('Address lister') == False:
		sys.exit()
	list_addresses()