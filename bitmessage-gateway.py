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
	'domain_name' : 'yourdomain.com',
	'mail_folder' : '/home/youruser/MailDir/new/',
	'log_filename' : '/var/log/bitmessage-gateway.log',
	'process_interval' : 10,
	'generic_receive_address_label' : 'yourdomain.com Generic Receive Address',
	'registration_address_label' : 'yourdomain.com Registration Address',
	'deregistration_address_label' : 'yourdomain.com Deregistration Address',
	'bug_report_address_bitmessage' : 'your bitmessage address',
	'bug_report_address_email' : 'support@yourdomain.com',
	'debug' : True,
	'respond_to_invalid' : True,
	'wait_for_send_op' : False
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
	'support' : True,
	'bug' : True,
	'bugs' : True
}


## setup logging
logging.basicConfig(filename=config['log_filename'],level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

## address book and address list placeholders
address_list = {}
addressbook = {}

## connect to Bitmessage API
def api_connect(module):

	global api

	## connect to API
	api['conn'] = xmlrpclib.ServerProxy('http://' + api['username'] + ':' + api['password'] + '@' + api['host'] + ':' + api['port'] + '/')
	
	## check if API is responding
	try:
		response = api['conn'].add(2,2)
		logging.info(module + " module loaded Bitmessage API and started")

		## load addresses and addressbook
		global address_list, addressbook
		address_list = get_address_list()
		addressbook = get_addressbook()	

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


## check if a bitmessage address has already registered a username
def is_address_registered(address):

	global addressbook

	for label in addressbook:
		if addressbook[label] == address:
			return True
	return False


## find username from address
def find_username(address):

	global addressbook

	for label in addressbook:
		if addressbook[label] == address:
			return label
	return False


## check if username is banned
def is_banned_username(username):

	global banned_usernames
	if username in banned_usernames:
		return True
	else:
		return False


## find mapping for generated bitmessage ID to internet-bound email address
def find_internet_mapping(address):

	global address_list
	for email,bound_add in address_list.iteritems():
		if bound_add == address:
			return email
	return False


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
def generate_sender_address(email):

	global api

	## generate random address
	time_start = time.time()
	address = api['conn'].createRandomAddress(base64.b64encode(email))
	time_stop = time.time()
	time_total = int(time_stop - time_start)
	logging.info('Generated sender address for ' + email + ' in ' + str(time_total) + ' seconds')

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
			time.sleep(10)

			## show API responses
			if config['debug']:
				logging.debug(api['conn'].getStatus(ackData))

		## time and log successful send
		time_stop = time.time()
		time_total = int(time_stop - time_start)
		logging.info('Sent bitmessage from ' + from_email + ' to ' + to_email  + ' in ' + str(time_total) + ' seconds')

	## just queue message
	ackData = api['conn'].sendMessage(bm_to_address, bm_from_address, bm_subject, bm_body, 2)
	if config['debug']:
		logging.info('Sent bitmessage from ' + from_email + ' to ' + to_email + ' : QUEUED FOR DELIVERY , API response: ' + ackData)
	else:
		logging.info('Sent bitmessage from ' + from_email + ' to ' + to_email + ' : QUEUED FOR DELIVERY')


## check for new bitmessages
def get_bitmessages():

	global api 
	return json.loads(api['conn'].getAllInboxMessages())['inboxMessages']


## delete bitmessage
def delete_bitmessage(msgid):

	global api, debug
	result = api['conn'].trashMessage(msgid)
	if config['debug']:
		logging.debug('Deleted bitmessage, API response: ' + result)
	else:
		logging.info('Deleted bitmessage')


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

	## send failed
	except SMTPException as e:
   		logging.error('Could not send email from ' + sender + ' to ' + receiver + ' : ' + e)
	
	server.quit()


## list known addresses
def list_addresses():

	
	global address_list, addressbook

	## print all addresses 
	print "\n####################################\nExternal Address List\n####################################"
	for tmp_email in address_list:
		print tmp_email + "\t\t\t" + address_list[tmp_email]
	print ''
	
	print "\n####################################\nInternal Address List\n####################################"
	for tmp_email in addressbook:
		print tmp_email + "\t\t\t" + addressbook[tmp_email]
	print ""


## add email @godark.ca with bitmessage address
def add_new_user(address, email):

	global api, config
	if config['debug']:
		logging.debug('Registered new user, API response: ' + api['conn'].addAddressBookEntry(address, base64.b64encode(email)))
	else:
		api['conn'].addAddressBookEntry(address, base64.b64encode(email))
		logging.info('Registered new user ' + email)


## send out registration confirmation
def send_registration_verification(bm_to_address, bm_from_address, email):

	global api, config, address_list

	## build message
	subject = base64.b64encode('Registration Request Accepted')
	body = base64.b64encode('Thank you for your registration request for ' + email + '. Your account is now set up and ready to use!\r\n\r\nTo deregister your email, simply send a message from this address to ' + address_list[config['deregistration_address_label']] + '.\r\n\r\nNote: this service is still in Beta! Please send any comments/bug reports to\r\n' + config['bug_report_address_bitmessage'] + '  or\r\n' + config['bug_report_address_email'] + '.\r\n\r\n***************************\r\nIf you send a message and Bitmessage does not show the message as acknowledged, please wait 5 minutes before sending again!\r\n***************************')

	## send message
	send_bitmessage(bm_to_address, bm_from_address, subject, body, 'register@' + config['domain_name'], email)


## send out deregistration confirmation
def send_deregistration_verification(bm_to_address, bm_from_address, email):

	global api, config

	## build message
	subject = base64.b64encode('Deregistration Request Processed')
	body = base64.b64encode('Thank you for your deregistration request for ' + email + '. Your account has now been removed. Bon vogage!')

	## send message
	send_bitmessage(bm_to_address, bm_from_address, subject, body, 'deregister@' + config['domain_name'], email)


## send registration request response for bad requests
def send_registration_response(badFormat, badUsername, bm_to_address, bm_from_address, email):

	global api, config

	## build message
	subject = base64.b64encode('Registration Request Denied')
	if badFormat:
		logging.warn('Received invalid registration request from ' + bm_to_address + ' for ' + email + ' (Invalid Username)')
		body = base64.b64encode('Your registration request for username ' + email + ' was dened because the submitted username format is invalid.\r\n\r\nPlease register an alpha-numeric only username with a length of 4-20 characters. We will add the ' + config['domain_name'] + ' suffix automatically!')
	else:
		logging.warn('Received invalid registration request from ' + bm_to_address + ' for ' + email + ' (Username In Use)')
		body = base64.b64encode('Your registration request for username ' + email + ' was dened because the username is already in use!')
	
	## send message
	if config['respond_to_invalid']:
		send_bitmessage(bm_to_address, bm_from_address, subject, body, 'register@godark.ca', 'Denied Registration Request')


## delete address
def delete_address(address):

	global api, config

	## try to delete and don't worry about if it actually goes through
	api['conn'].deleteAddressBookEntry(address)
	api['conn'].deleteAddress(address)

	if config['debug']:
		logging.debug('Deleted bitmessage address, ' + address)


## check for new bitmessages to process
def check_messages():

	global config, addressbook, address_list

	## get all messages
	all_messages = json.loads(api['conn'].getAllInboxMessages())['inboxMessages']	

	## if no messages
	if not all_messages:
		return

	## loop through messages to find unread
	for a_message in all_messages:

		## if already read, delete and break
		if a_message['read'] == 1:
			delete_bitmessage(a_message['msgid'])
			continue

		## if the message is unread, load it by ID to trigger the read flag
		message = json.loads(api['conn'].getInboxMessageByID(a_message['msgid'], True))['inboxMessage'][0]

		## if a blank message was returned
		if not message:
			logging.error('API returned blank message when requesting a message by msgID')
			delete_bitmessage(bm_id)
			continue

		## find message ID
		bm_id = message['msgid']

		## check if receive address is a DEregistration request
		if message['toAddress'] == address_list[config['deregistration_address_label']]:

			## check if address is registered
			is_registered = is_address_registered(message['fromAddress'])

			## if the sender is actually registered and wants to deregister
			if is_registered:

				## find username
				deregistered_email = find_username(message['fromAddress'])

				## process deregistration
				logging.info('Processed deregistration request for user ' + deregistered_email)
				delete_address(message['fromAddress'])
				addressbook.pop(deregistered_email, None)

				## send deregistration confirmation email
				send_deregistration_verification(message['fromAddress'], address_list[config['deregistration_address_label']], deregistered_email)

			## bogus deregistration request
			else:
				logging.warn('Purged malicious deregistration bitmessage from ' + message['fromAddress'])


		## check if receive address is a registration request
		elif message['toAddress'] == address_list[config['registration_address_label']]:

			## find requested username
			proposed_registration_user = base64.b64decode(message['subject'])

			#full_registration_user = registration_user + '@' + config['domain_name']
			valid_one = re.match('^[\w]{4,20}$', proposed_registration_user) is not None
			valid_two =  re.match('^[\w]{4,20}@' + config['domain_name'] + '$', proposed_registration_user) is not None

			## if username is valid check if it's available
			if valid_one or valid_two:
				
				# strip domain if they sent it during registration
				if valid_one:
					full_registration_user = proposed_registration_user + '@' + config['domain_name']
					registration_user = proposed_registration_user
				else:
					full_registration_user = proposed_registration_user
					registration_user = proposed_registration_user.split('@')[0]

				## check if address is already registered to a username or is banned
				is_double_registered = is_address_registered(message['fromAddress'])
				is_banned = is_banned_username(registration_user)

				## if username is available and not banned and not double registered
				if not full_registration_user in addressbook and not is_banned and not is_double_registered:

					logging.info('Received registration request for username ' + full_registration_user)
					add_new_user(message['fromAddress'], full_registration_user)
					addressbook[full_registration_user] = message['fromAddress']
					print addressbook
					send_registration_verification(message['fromAddress'], address_list[config['registration_address_label']], full_registration_user)

				## username already taken
				else:
					send_registration_response(False, True, message['fromAddress'], address_list[config['registration_address_label']], full_registration_user)
					
			## if bad username format
			else:
				send_registration_response(True, False, message['fromAddress'], address_list[config['registration_address_label']], proposed_registration_user)


		## check if receive address is the generic receive address or specific address
		else:

			## find message id
			bm_id = message['msgid']

			## if user is not registered, purge
			is_registered = is_address_registered(message['fromAddress'])
			if not is_registered:

				logging.warn('Purged bitmessage from non-registered user ' + message['fromAddress'])
				delete_bitmessage(bm_id)
				continue

			## if user is registered, find their username @ domain
			else:
				bm_sender = find_username(message['fromAddress'])

			## if receive address is the generic receiver
			if message['toAddress'] == address_list[config['generic_receive_address_label']]:

				bm_receiver = re.findall(r'[\w\.-]+@[\w\.-]+\.[\w]+', base64.b64decode(message['subject']))
				if len(bm_receiver) > 0:
					bm_receiver = bm_receiver[0]
				bm_subject = ''

			## if bound for unknown address, see if it maps back to an email
			else:
				bm_receiver = find_internet_mapping(message['toAddress'])
				bm_subject = base64.b64decode(message['subject'])

			## if there is no receiver mapping or the generic address didnt get a valid outbound email, deny it
			if not bm_receiver:
				logging.warn('Received and purged bitmessage with unknown recipient (likely generic address and bad subject)')
				delete_bitmessage(bm_id)
				continue

			## handle removal of embedded BMG-FROM:: tag for replies
			bm_subject = bm_subject.replace('BMG-FROM::' + bm_receiver + ' | ', '');

			## get message contents
			bm_body = base64.b64decode(message['message'])	

			## send message and delete bitmessage, bitches
			send_email(bm_receiver, bm_sender, bm_subject, bm_body, bm_id)


		## remove message
		delete_bitmessage(bm_id)
		


## check for new mail to process
def check_emails():

	global config, address_list, addressbook

	## find new messages in folders
	dir = os.listdir(config['mail_folder'])

	## no new mail
	if not dir:
		return

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
			msg_sender = config['generic_receive_address_label']
		else:
			msg_sender    = re.findall(r'[\w\.-]+@[\w\.-]+.[\w]+', msg_sender)[0]

		## find email details
		msg_recipient = msg_headers["To"]

		## check if we have valid sender and recipient details
		if not msg_sender or not msg_recipient:
			logging.warn('Malformed email detected and purged')
			delete_email(k)
			continue

		## check if we have a recipient address for the receiving email
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

		## print message status and set correct subject
		## if bounded email
		if msg_sender == config['generic_receive_address_label']:
			logging.info('Received bounced email... forwarding to ' + msg_recipient)
			bm_subject = base64.b64encode('postmaster@' + config['domain_name'])
		## if normal email
		else:
			logging.info('Received inbound email request from ' + msg_sender + ' to ' + msg_recipient)
			bm_subject = base64.b64encode('BMG-FROM::' + msg_sender + ' | ' + msg_subject)

		## send message to bitmessage address
		bm_body = base64.b64encode(msg_body)
		send_bitmessage(bm_to_address, bm_from_address, bm_subject, bm_body, msg_sender, msg_recipient)

		## remove email file
		delete_email(k)


## main  
parser = argparse.ArgumentParser(description='An email <-> bitmessage gateway.')
parser.add_argument('-l','--list', help='List known internal and external addresses',required=False, action='store_true')
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
	delete_address(args.delete)	

elif args.add:
	if api_connect('Address adder') == False:
		sys.exit()
	generate_sender_address(args.add)

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
