bitmessage-email-gateway
========================

This software is a bi-directional email gateway implementation for the Bitmessage network.

This software will take a standard email MTA setup using a catchall address and MailDir as its storage type and will act as a email <-> bitmessage gateway.

For more information about Bitmessage, please visit https://www.bitmessage.org

For an example of a live version of this software, please visit https://www.godark.ca


## Features
 * Allows users to register for and deregister from the service via Bitmessage
 * Drops message requests from unregistered users
 * Allows registered users to send emails from their registered account to the Internet using their Bitmessage client software (see https://www.godark.ca for more information)
 * Allows Internet users to send messages to registered users using the user's @domain.com email address
 * Auto purges bitmessages and emails immediately after sending
 * Transparently encrypts emails destined for addresses with published PGP keys (multiple key servers supported)

## System Requirements
 * Debian 7 (other Linux distributions will also work)
 * Python 2.7.5 (most stable version for the Bitmessage application)
 * Bitmessage with API enabled (see https://bitmessage.org/wiki/Compiling_instructions and https://bitmessage.org/wiki/API_Reference) 
 * Postfix (or similar MTA) setup with a catchall-address @your-domain.com that forwards all messages to the user 'bitmessage' and uses the MailDir storage method

## Python Dependencies
 * Gnupg
 * BeautifulSoup3
 * Possibly others that I have forgotten about
 
## Installation Instructions
 * Download and install Bitmessage. Make sure it is running and listening via it's API port (https://bitmessage.org/wiki/API_Reference)
 * Add a linux user for the software
```
useradd bitmessage
passwd bitmessage
su bitmessage
```
 * Install Postfix (or other MTA) for your domain name and make sure a catch-all address is set up to forward all emails to bitmessage@your-domain.com
 * Make sure Postfix (or other MTA) is configured to use MailDir as its storage method! You can send a test email to catchall@your-domain.com to see if it's delivered to /home/bitmessage/MailDir/new
 * Download the newest version of this software and unzip
```
wget https://github.com/darkVPN/bitmessage-email-gateway/archive/master.zip
unzip master.zip
rm -rf ./master.zip
cd bitmessage-email-gateway/
```
 * Open bitmessage-gateway.py and edit the Bitmessage API connection settings:
```
## API connection information
api = {
	'conn' : '',
	'username' : 'your-bitmessage-api-user',
	'password' : 'your-bitmessage-api-password',
	'host' : '127.0.0.1',
	'port' : '8442'

}
```
 * Next, modify the application's general settings:
```
## system configuration details
config = {
	'domain_name' : 'your-domain.com',
	'mail_folder' : '/home/bitmessage/MailDir/new/',
	'log_filename' : '/var/log/bitmessage-gateway.log',
	'process_interval' : 10,
	'receiving_address_label' : 'your-domain.com Generic Receive Address',
	'sending_address_label' : 'your-domain.com Generic Sender Address',
	'registration_address_label' : 'your-domain.com Registration Address',
	'deregistration_address_label' : 'your-domain.com Deregistration Address',
	'bug_report_address_bitmessage' : 'you-bitmessage-address',
	'bug_report_address_email' : 'your-email',
	'debug' : True,
	'respond_to_invalid' : True
}
```
 * Setup the log file for use:
```
touch /var/log/bitmessage-gateway.log
chown bitmessage:bitmessage /var/log/bitmessage-gateway.log
```
 * Add the required bitmessage addresses for your service (registration, deregistration, sender, and receiver'):
```
chmod +x bitmessage-gateway.py
./bitmessage-gateway.py -a 'your-domain.com Generic Receive Address'
./bitmessage-gateway.py -a 'your-domain.com Generic Sender Address'
./bitmessage-gateway.py -a 'your-domain.com Registration Address'
./bitmessage-gateway.py -a 'your-domain.com Deregistration Address'
```
 * Check to make sure all required addresses have been added successfully. Note: you should see the four labels (and corresponding addresses) that you set in your config!
```
./bitmessage-gateway.py -l
```
An example response:
```
####################################
Internal Address List
####################################
goDark Deregistration Address                   BM-2cTDKufxNFY6iAafxartJUHodHDQ8BabNR
goDark Registration Address                     BM-2cX1rp2LmTxn2yZERVuMGqCNuTbBwqLA4e
goDark Generic Receive Address                  BM-2cW5Yvp5x9mL8gwjGdm65H9ombKG6JvRHg
goDark Generic Sender Address                   BM-2cWPQvSfwEzDnG8xd8DGwz1p3Lj8FGk3tT
```
 * Now it's time to distribute these addresses to your users via a website, Twitter, etc!
 
 When users send a message to your 'domain.com Registration Address' bitmessage address with their desired username in the subject field, the system will automatically register them and send a welcome email. This welcome email describes how to use the system and how to contact you about bugs/comments. You can change the welcome email content by editing the bitmessage-gateway.py script.

 Users can deregister by sending a message to the 'domain.com Deregistration Address' bitmessage address listed in the last step.
 
 Users can send outbound emails to the Internet by sending a message to the 'domain.com Receive Address' bitmessage address with the destination email in the subject field. Outbound emails destined for addresses with known public PGP keys will be encrypted automatically. Email responses will automatically be forwarded to your users.
 
 People of the Internets can send emails to your users by simply emailing their username@domain.com address.

 * Run the application!
```
./bitmessage-gateway.py
```

## Comments / Bug Reports
Fork away if you're a developer ;)

Email: admin@godark.ca

Bitmessage: BM-2cWVu29tHfapydEsyQh6acsm4GX7mWE6FY

