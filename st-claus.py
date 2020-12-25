# Name:			st-claus.py
# Type:			Subdomain Takeover finder
# Author:		MrSaighnal
# date:			12/24/2020
# official Repository:	https://github.com/MrSaighnal/ST-Claus/
# .______________________________________________.
# |					         |
# |  Don't use this script for illegal purposes  |
# |______________________________________________|


import requests
import dns
import dns.resolver
import re
import os
import sys
import socket
from bs4 import BeautifulSoup
import urllib3


# set the colors
# Python program to print 
# colored text and background 
class colors: 

    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg: 
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg: 
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[103m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'

# fingerprint by https://github.com/EdOverflow/can-i-take-over-xyz
fingerprints = ["Web Site Not Found",
	"Sorry, this page is no longer available.",
	"If this is your website and you've just created it, try refreshing in a minute",
	"The specified bucket does not exist",
	"Repository not found",
	"Trying to access your account?",
	"404 Not Found",
	"Please try again or try Desk.com free for 14 days.",
	"Fastly error: unknown domain:",
	"The feed has not been found.",
	"404 Not Found",
	"404: This page could not be found.",
	"The thing you were looking for is no longer here, or never was",
	"There isn't a Github Pages site here.",
	"NoSuchBucketThe specified bucket does not exist.",
	"404 Blog is not found",
	"We could not find what you're looking for.",
	"No settings were found for this company:",
	"No such app",
	"Uh oh. That page doesn't exist.",
	"is not a registered InCloud YouTrack",
	"No Site For Domain",
	"It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
	"Unrecognized domain",
	".ngrok.io not found",
	"404 error unknown site!",
	"This public report page has not been activated by the user",
	"Project doesnt exist... yet!",
	"Sorry, this shop is currently unavailable.",
	"This job board website is either expired or its domain name is invalid.",
	"page not found",
	"project not found",
	"Whatever you were looking for doesn't currently exist at this address",
	"Please renew your subscription",
	"Non-hub domain, The URL you've accessed does not provide a hub.",
	"The requested URL was not found on this server.",
	"page not found",
	"This UserVoice subdomain is currently available!",
	"The page you are looking for doesn't exist or has been moved.",
	"Do you want to register ",
	"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
	"Help Center Closed"
	]

vulnerable = []


def startup():
	os.system("clear")
	print('  .-""-.' + colors.fg.lightred, colors.bold, "   [-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-]", colors.reset)
	print(" /,..___\\" + colors.fg.lightred, colors.bold, "  [-+-]", colors.fg.lightgreen, "       Subdomain Takeover Claus v0.1 ",  colors.fg.lightred, "      [-+-]", colors.reset)
	print('() {_____}' + colors.fg.lightred, colors.bold, " [-+-]", colors.fg.lightgreen, "           Author:", colors.fg.lightblue, "Mr Saighnal            ",  colors.fg.lightred, "[-+-]", colors.reset)
	print('  (/-@-@-\)' + colors.fg.lightred, colors.bold, "[-+-]", colors.fg.lightgreen, "     Email:", colors.fg.lightblue, "mrsaighnal@protonmail.com     ",  colors.fg.lightred, "[-+-]", colors.reset)
	print("  {`-=^=-'}" + colors.fg.lightred, colors.bold, "[-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-]", colors.reset)
	print("  {  `-'  } " + colors.fg.lightred, colors.bold, colors.bg.orange, "        DON'T USE THIS TOOL FOR ILLEGAL PURPOSE!        ", colors.reset)
	print('   {     }')
	print("    `---'" +  colors.reset, colors.fg.yellow, " usage: python3 st-claus.py list.txt", colors.reset)
	print("")
	if len(vulnerable) < 1:
		banner_color = colors.fg.red
	else:
		banner_color = colors.fg.green
		print(banner_color, colors.bold, "[+]", colors.reset, "Vulnerable domains found: " + str(len(vulnerable)))






def checkVuln(subdomain, origin):
	subdomain = (str(subdomain))[:-1]
	startup()
	print(colors.fg.yellow, colors.bold, "[-]", colors.reset, "Checking for vulnerability ", colors.bold, subdomain)	
	response = requests.get("https://" + subdomain)
	html = response.text
	soup = BeautifulSoup(html, "html.parser")
	only_text = soup.get_text()
	html = str(only_text)
	html = html.strip()
	html = ''.join(html.split())
	html = html.lower()
	#print(html)
	for ago in fingerprints:
		ago = (''.join(ago.split())).lower()
		if html.find(ago) >= 0:
			startup()
			print(colors.fg.green, colors.bold, "[+][+]", colors.reset, "Vulnerable " + subdomain, colors.bold)	
			vulnerable.append(origin + " to " + subdomain)






def checkCNAME(domain):
	startup()
	print(colors.fg.yellow, colors.bold, "[-]", colors.reset, "Looking for CNAME record in: ", colors.bold, domain)
	try:
		result = dns.resolver.resolve(domain, 'CNAME')
		for cnameval in result:
			startup()
			print(colors.fg.green, colors.bold, "[+]", colors.reset, "CNAME target address: ", colors.bold, cnameval.target)
			checkVuln(cnameval.target, domain)
	except:
		startup()
		print(colors.fg.red, colors.bold, "[-]", colors.reset, "No answer for the domain ", colors.bold, domain)





if __name__ == "__main__":
	startup()
	if len(sys.argv) == 1:
		print("Usage: python3 st-claus.py list.txt")
	else:
		# Open the file 
		f = open(sys.argv[1])
		# use readline() to read the first line 
		line = f.readline()
		# iterate the file
		while line:
			#check for CNAME records
			checkCNAME(line.rstrip())
			# use realine() to read next line
			line = f.readline()
		f.close()
		startup()
		for site in vulnerable:
			print(colors.fg.green, colors.bold, "[+]", colors.reset, "Vulnerable " + str(site))
