#!/usr/bin/python

## imports
import os
import re
import time
import datetime
import argparse
import logging
import sys
import threading
import signal
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

## system configuration details
config = {
	'domain_name' : 'godark.ca',
	'mail_folder' : '/home/your_user/MailDir/new/',
	'log_filename' : '/var/log/bitmessage-gateway.log',
	'process_interval' : 10,
	'generic_receive_address_label' : 'Your Generic Receive Address',
	'registration_address_label' : 'Your Registration Address',
	'debug' : True,
	'respond_to_invalid' : True,
	'wait_for_send_op' : False,
}


## API connection information
api = {
	'conn' : '',
	'username' : 'bmapi',
	'password' : '',
	'host' : '127.0.0.1',
	'port' : '8442'

}


## list of usernames to explicitly ban
banned_usernames = {
	'bitmessage' : True, 
	'register' : True,
	'admin' : True, 
	'administrator' : True, 
	'mailer' : True, 
	'mailer-daemon' : True, 
	'postmaster' : True, 
	'adm' : True,
	'mail' : True, 
	'news': True, 
	'operator' : True, 
	'ftp' : True, 
	'root' : True, 
	'dovecot' : True, 
	'exim' : True, 
	'post' : True, 
	'mailnull' : True, 
	'system' : True, 
	'manager' : True, 
	'abuse' : True, 
	'newsadm' : True, 
	'newsadmin' : True, 
	'webmaster' : True, 
	'security' : True, 
	'hostmaster' : True, 
	'info' : True, 
	'marketing' : True, 
	'sales' : True, 
	'support' : True
}


## setup logging
logging.basicConfig(filename=config['log_filename'],level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')


## connect to Bitmessage API
def api_connect(module):

	global api

	## connect to API
	api['conn'] = xmlrpclib.ServerProxy('http://' + api['username'] + ':' + api['password'] + '@' + api['host'] + ':' + api['port'] + '/')
	
	## check if API is responding
	try:
		response = api['conn'].add(2,2)
		logging.info(module + " module loaded Bitmessage API and started")
		return True
	
	except:
		logging.error('Could not connect to Bitmessage API ')
		return False
	

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

	global config
	
	try:
		f = open(config['mail_folder'] + k, 'r')
		message = f.read()
		return message
	except IOError:
		logging.error('Could not read email: ' + config['mail_folder'] + k)
		return


## delete email from file
def delete_email(k):

	global config

	try:
		os.remove(config['mail_folder'] + k)
	except OSError:
		logging.error('Could not delete email: ' + config['mail_folder'] + k)


## generate a bitmessage address for an incoming email adress
def generate_sender_address(email, output = False):

	global api

	## generate random address
	time_start = time.time()
	address = api['conn'].createRandomAddress(base64.b64encode(email))
	time_stop = time.time()
	time_total = int(time_stop - time_start)
	logging.info('Generated sender address for ' + email + ' in ' + str(time_total) + ' seconds')

	## if requested through console
	if output:
		print 'Generated sender address for ' + email + ' in ' + str(time_total) + ' seconds'

	return address


## send bitmessage
def send_bitmessage(bm_to_address, bm_from_address, bm_subject, bm_body, from_email, to_email):

	global api, config

	## only wait for send operation if set in config
	if config['wait_for_send_op']:

		## time and send message
		time_start = time.time()
		ackData = api['conn'].sendMessage(bm_to_address, bm_from_address, bm_subject, bm_body, 2)

		## wait for msg sent response from API
		while not "msgsent" in api['conn'].getStatus(ackData):
			time.sleep(5)

			## show API responses
			if config['debug']:
				logging.debug(api['conn'].getStatus(ackData))

		## time and log successful send
		time_stop = time.time()
		time_total = int(time_stop - time_start)
		logging.info('Sent bitmessage from ' + from_email + ' to ' + to_email  + ' in ' + str(time_total) + ' seconds')

	## just queue message
	ackData = api['conn'].sendMessage(bm_to_address, bm_from_address, bm_subject, bm_body, 2)
	logging.info('Sent bitmessage from ' + from_email + ' to ' + to_email + ' : QUEUED FOR DELIVERY')


## check for new bitmessages
def get_bitmessages():

	global api 
	return json.loads(api['conn'].getAllInboxMessages())['inboxMessages']


## delete bitmessage
def delete_bitmessage(msgid):

	global api, debug
	api['conn'].trashMessage(msgid)
	if config['debug']:
		logging.debug('Deleted bitmessage')


## send outbound email
def send_email(receiver, sender, subject, body, bm_id):

	## build message
	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = receiver
	msg['Subject'] = subject
	msg.attach(MIMEText(body, 'plain'))
	server = smtplib.SMTP('localhost')
	server.set_debuglevel(1)
	text = msg.as_string()

	## send message
	try:
		server.sendmail(sender, receiver, text)
   		logging.info('Sent email from ' + sender + ' to ' + receiver) 
		delete_bitmessage(bm_id)
	except SMTPException as e:
   		logging.error('Could not send email from ' + sender + ' to ' + receiver + ' : ' + e)
	
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


## add email @godark.ca with bitmessage address
def add_new_user(address, email):

	global api, config
	api['conn'].addAddressBookEntry(address, base64.b64encode(email))
	logging.info('Registered new user ' + email)


## send out registration confirmation
def send_registration_verification(bm_to_address, bm_from_address, email):

	global api, config

	## build message
	subject = base64.b64encode('Registration Request Accepted')
	body = base64.b64encode('Thank you for your registration request for ' + email + '. Your account is now set up and ready to use!\r\n\r\nTo deregister your email, simply send a message back to this registration service with the subject set as \'deregister\' (without quotes).')

	## send message
	send_bitmessage(bm_to_address, bm_from_address, subject, body, 'register@' + config['domain_name'], email)


## send out deregistration confirmation
def send_deregistration_verification(bm_to_address, bm_from_address, email):

	global api, config

	## build message
	subject = base64.b64encode('Deregistration Request Processed')
	body = base64.b64encode('Thank you for your deregistration request for ' + email + '. Your account has now been remove. Bon vogage!')

	## send message
	send_bitmessage(bm_to_address, bm_from_address, subject, body, 'deregister@' + config['domain_name'], email)


## send registration request response for bad requests
def send_registration_response(badFormat, badUsername, bm_to_address, bm_from_address, email):

	global api, config

	## build message
	subject = base64.b64encode('Registration Request Denied')
	if badFormat:
		logging.warn('Received invalid registration request from ' + bm_to_address + ' for ' + email + ' (Invalid Username)')
		body = base64.b64encode('Your registration request for username ' + email + ' was dened because the submitted username format is invalid.\r\n\r\nPlease register an alpha-numeric only username with a length of 4-20 characters.')
	else:
		logging.warn('Received invalid registration request from ' + bm_to_address + ' for ' + email + ' (Username In Use)')
		body = base64.b64encode('Your registration request for username ' + email + ' was dened because the username is already in use!')
	
	## send message
	if config['respond_to_invalid']:
		send_bitmessage(bm_to_address, bm_from_address, subject, body, 'register@godark.ca', 'Denied Registration Request')


## delete address
def delete_address(address, from_console = False):

	## try to delete and don't worry about if it actually goes through
	global api, config
	api['conn'].deleteAddressBookEntry(address)
	api['conn'].deleteAddress(address)
	
	if from_console:
		print "Deleted address " + address
	if config['debug']:
		logging.debug('Deleted bitmessage address ' + address)


## check for new bitmessages to process
def check_messages():

	global config

	## get all messages
	all_messages = json.loads(api['conn'].getAllInboxMessages())['inboxMessages']	

	## if no messages
	if not all_messages:
		return

	## get all addresses 
	address_list = get_address_list()
	addressbook = get_addressbook()	

	## loop through messages to find unread
	for a_message in all_messages:

		## if already read, delete and break
		if a_message['read'] == 1:
			delete_bitmessage(a_message['msgid'])
			continue

		## if the message is unread, load it by ID to trigger the read flag
		message = json.loads(api['conn'].getInboxMessageByID(a_message['msgid'], True))['inboxMessage'][0]

		## find message ID
		bm_id = message['msgid']

		## check if receive address is a registration request
		if message['toAddress'] == address_list[config['registration_address_label']]:

			## check for deregister request
			msg_subject = base64.b64decode(message['subject']).lower()
			if msg_subject == 'deregister' or msg_subject == 'de-register' or msg_subject == 'unregister' or msg_subject == 'un-register':

				## delete address from addressbook
				deregistered_email = ''
				for tmp_email, tmp_address in addressbook.iteritems():
					if tmp_address == message['fromAddress']:
						deregistered_email = tmp_email

				## if the sender is actually registered and wants to deregister
				if deregistered_email:

					logging.info('Processed deregistration request for user ' + deregistered_email)
					delete_address(message['fromAddress'])
					addressbook.pop(deregistered_email, None)

					## send deregistration confirmation email
					send_deregistration_verification(message['fromAddress'], address_list[config['registration_address_label']], deregistered_email)

				## bogus deregistration request
				else:
					logging.warn('Purged malicious deregistration bitmessage from ' + message['fromAddress'])


			## check for registration request
			else:

				## find requested username
				registration_user = base64.b64decode(message['subject'])
				full_registration_user = registration_user + '@' + config['domain_name']
				valid = re.match('^[\w]{4,20}$', registration_user) is not None

				## if username is valid check if it's available
				if valid:
					
					global banned_usernames

					## if username is available
					if not full_registration_user in addressbook and not registration_user in banned_usernames:

						logging.info('Received registration request for username ' + full_registration_user)
						add_new_user(message['fromAddress'], full_registration_user)
						addressbook[full_registration_user] = message['fromAddress']
						send_registration_verification(message['fromAddress'], address_list[config['registration_address_label']], full_registration_user)

					## username already taken
					else:
						send_registration_response(False, True, message['fromAddress'], address_list[config['registration_address_label']], full_registration_user)
						
				## if bad username format
				else:
					send_registration_response(True, False, message['fromAddress'], address_list[config['registration_address_label']], full_registration_user)

			## remove message
			delete_bitmessage(bm_id)
			continue

		## check if sender has an outbound email address, else purge
		bm_sender = ''
		for tmp_email, tmp_address in addressbook.iteritems():
			if tmp_address == message['fromAddress']:
				bm_sender = tmp_email
		if not bm_sender:
			logging.warn('Purged bitmessage from non-registered user ' + bm_sender)
			delete_bitmessage(bm_id)
			continue

		## if receive address is bound to an email
		bm_receiver = ''
		bm_subject = ''
		if not message['toAddress'] == address_list[config['generic_receive_address_label']]:
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
			logging.warn('Received and purged message with unknown recipient (likely generic address and bad subject)')
			delete_bitmessage(bm_id)
			continue

		## handle removal of embedded BMG-FROM:: tag for replies
		bm_subject = bm_subject.replace('BMG-FROM::' + bm_receiver + ' | ', '');

		## get message contents
		bm_body = base64.b64decode(message['message'])	

		## send message and delete bitmessage, bitches
		send_email(bm_receiver, bm_sender, bm_subject, bm_body, bm_id)


## check for new mail to process
def check_emails():

	## find new messages in folders
	global config
	dir = os.listdir(config['mail_folder'])

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
			logging.error('Could not open email file: ' + k)
			continue

		## extract header
		msg_headers = Parser().parsestr(msg_raw)

		## check if email was valid
		if not msg_headers:
			logging.error('Malformed email detected and purged')
			delete_email(k)
			continue

		## find email source and dest addresses
		msg_sender    = msg_headers["Return-path"]

		## failed delivery email
		if msg_sender == '<>':
			logging.warn('Bounced email detected and purged')
			delete_email(k)
			continue

		## find email details
		msg_sender    = re.findall(r'[\w\.-]+@[\w\.-]+.[\w]+', msg_sender)[0]
		msg_recipient = msg_headers["To"]

		## check if we have valid sender and recipient details
		if not msg_sender or not msg_recipient:
			logging.warn('Malformed email detected and purged')
			delete_email(k)
			continue

		## check if we have a recipient address for the receiving email
		addressbook = get_addressbook()
		if not msg_recipient in addressbook:
			logging.warn('Purged email destined for unknown user ' + msg_recipient)
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
		logging.info('Received outbound email request from ' + msg_sender + ' to ' + msg_recipient)

		## send message to bitmessage address
		bm_subject = base64.b64encode('BMG-FROM::' + msg_sender + ' | ' + msg_subject)
		bm_body = base64.b64encode(msg_body)
		send_bitmessage(bm_to_address, bm_from_address, bm_subject, bm_body, msg_sender, msg_recipient)

		## remove email file
		delete_email(k)


## main  
parser = argparse.ArgumentParser(description='An email <-> bitmessage gateway.')
parser.add_argument('-l','--list', help='List known internal and external messages',required=False, action='store_true')
parser.add_argument('-d','--delete', help='Delete an address',required=False, default=False)
parser.add_argument('-a','--add', help='Generate a new bitmessage address with given label',required=False, default=False)

args = parser.parse_args()


## call correct function
if args.list == True:
	if api_connect('Address lister') == False:
		sys.exit()
	list_addresses()

elif args.delete:
	if api_connect('Address deleter') == False:
		sys.exit()
	delete_address(args.delete, True)	

elif args.add:
	if api_connect('Address adder') == False:
		sys.exit()
	generate_sender_address(args.add, True)

else:
	if api_connect('Main') == False:
		sys.exit()

	## run managers in threads
	while True:

		email_thread = threading.Thread(target=check_emails)
		message_thread = threading.Thread(target=check_messages)
		email_thread.start()
		message_thread.start()
		email_thread.join()
		message_thread.join()
		time.sleep(config['process_interval'])
