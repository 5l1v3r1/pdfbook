#!/usr/bin/env python
#Copyright (c) 2009 Jeff Bryner
#python script to gather facebook artifacts from a pd process memory dump

#example: 
#
#on windows box, use pd from www.trapkit.de ala: 
#pd -p 1234> 1234.dump
#
#where 1234 is a running instance of IE/firefox/browser
#
#on linux box do:
#strings -el 1234.dump> memorystrings.txt
#./pdfbook.v1.py -f memorystrings.txt
#
#It'll find what it can out of the memory image 

#This program is free software; you can redistribute it and/or modify it under
#the terms of the GNU General Public License as published by the Free Software
#Foundation; either version 2 of the License, or (at your option) any later
#version.

#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along with
#this program; if not, write to the Free Software Foundation, Inc.,
#59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


import sys
import os
import types
import struct
from time import *
import getopt
import array
import re
import sha

safestringre=re.compile('[\x80-\xFF]')
printablestringre=re.compile('[\x80-\xFF\x00-\x1F]')
ipre=re.compile('(?:\d{1,3}\.){3}\d{1,3}')


#used to remove the noise from the output since we're not a browser
#sometimes there are double quotes, sometimes single. I'd or them with | but it messes up the matching pair. Brute force it is.
onclickre=re.compile(r"""(onclick=\".*?\")""",re.IGNORECASE)	
onclicksinglere=re.compile(r"""(onclick=\'.*?\')""",re.IGNORECASE)
onmousedownre=re.compile(r"""(onmousedown=\".*?\")""",re.IGNORECASE)	
onmousedownsinglere=re.compile(r"""(onmousedown=\'.*?\')""",re.IGNORECASE)

spanendre=re.compile(r"""</span>""",re.IGNORECASE)

#begin
#Facebook specific regexes
#
#story setups used to get userids and name associations.
#UIIntentionalStory.setup($("div_story_50930182619061234_115316170123"), {"title":"Hide","unfollow":{"users":[{"id":543391123,"name":"Joe Facebook","firstName":"Joe","hideString":"Hide Joe"}]}});
fbookintentionalstoryre= re.compile(r"""(UIIntentionalStory.setup.*(\"id\":(.*),\"name"\:"(.*)".*"firstName"))""", re.IGNORECASE)

#'what's on your mind'
#"userInfos":{"1421688012":{"name":"John Doe","firstName":"John","thumbSrc":"http:\/\/profile.ak.fbcdn.net\/v228\/472\/64\/q1421688012_3296.jpg","status":"StatusText goes here.","statusTime":1249259734,"statusTimeRel":"on Sunday","enableVC":false}}
fbookuserinfosre=re.compile(r"""(userInfos":{"(.*?)":{("name.*?)\})""",re.IGNORECASE)

fbookrecentactivityre=re.compile(r"""UIRecentActivity_Body">(.*?)<span""", re.IGNORECASE|re.MULTILINE)

#news/live feed items
#firefox only regex::
#fbookintentionalstorymessagere=re.compile(r"""<h3 class=\"UIIntentionalStory_Message.*?<span class=\"UIIntentionalStory_Names\">(.*?)</h3""", re.IGNORECASE|re.DOTALL)

#universal regex accounts for 
#	lack of/presence of quotes
#	distance between ending </h3> entry from the beginning <h3> entry since memory strings are messy
#	IE only stuff in the <h3 class= entry
fbookintentionalstorymessagere=re.compile(r"""<h3 class=\"{0,1}UIIntentionalStory_Message.{1,90}?UIIntentionalStory_Names.{1,90}?>(.{5,1000}?)</h3""",re.IGNORECASE|re.DOTALL)


#2009/10 UI change has differing class names: 
#	<h3 class="GenericStory_Message" data-ft="{&quot;type&quot;:&quot;msg&quot;}"><a href="http://www.facebook.com/profile.php?id=786299971&amp;ref=nf" class="GenericStory_Name" onclick='ft("4:10:46:786299971:1:::0:h:::168262982484");'>Scott Bryner</a> slept for 12 hours last night.</h3>
fbookgenericstorymessagere=re.compile(r"""<h3 class=\"{0,1}GenericStory_Message.{1,190}?GenericStory_Name.{1,90}?>(.{5,1000}?)</h3""",re.IGNORECASE|re.DOTALL)


#try to get the fbook account owner
#they only show remove buttons to owners
#<a onclick='ProfileStream.hideStory("div_story_4aa5d7bd29cfd0a12915885", "1421688057", "5377451560287089488", 72, ""); return false;' class="UIButton UIButton_Gray UIActionButton_SuppressMargin UIButton_Suppressed UIActionButton" href="#"><span class="UIButton_Text">Remove</span></a>
fbookremovebuttonre=re.compile(r"""(<a onclick='ProfileStream.hideStory\("div.{1,30}?", "(.{1,30}?)".{1,300}?<span class="UIButton_Text">Remove</span></a>)""",re.IGNORECASE|re.DOTALL)


#regexes for facebook emails
# 	start wtih <div class="GBThreadMessageRow_Main">
#	end with three </div> but we only grab until GBThreadMessageRow_Body_Attachment since multi divs live in the attachment sometimes
#author
#        <a class="GBThreadMessageRow_AuthorLink" href="http://www.facebook.com/fishbonemusic">Fishbone</a>
#date
#      <span class="GBThreadMessageRow_Date">October 19 at 3:38pm</span>
#body
#	<div class="GBThreadMessageRow_Body"><div class="GBThreadMessageRow_Body_Content">blah, blah, blah</div>
fbookemailre=re.compile(r"""<div class=\"{0,1}GBThreadMessageRow_Main\"{0,1}>(.{1,5000})?<div class=\"{0,1}GBThreadMessageRow_Body_Attachment\"{0,1}>""",re.IGNORECASE|re.DOTALL)
fbookemailauthorre=re.compile(r"""<a class=\"{0,1}GBThreadMessageRow_AuthorLink\"{0,1} href=\"(.{1,100})?\">(.{1,300})?</a>""",re.IGNORECASE|re.DOTALL)
fbookemaildatere=re.compile(r"""<span class=\"{0,1}GBThreadMessageRow_Date\"{0,1}>(.{1,100})?</span>""",re.IGNORECASE|re.DOTALL)
fbookemailbodyre=re.compile(r"""<div class=\"{0,1}GBThreadMessageRow_Body_Content\"{0,1}>(.{1,5000})?</div>\s{0,10}<div class=\"{0,1}GBThreadMessageRow_ReferrerLink\"{0,1}>""",re.IGNORECASE|re.DOTALL)


def safestring(badstring):
        """makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        return safestringre.sub(lambda c: 'char#%d;' % ord(c.group(0)),badstring)

def printablestring(badstring):
	"""only printable range..i.e. upper ascii minus lower junk like line feeds, etc"""
	return printablestringre.sub('',badstring)

def parseOptions():
	options = {'file'	:'',
		   'verbose'	: False,
		   'debug'	: False
		  }
	helpstr = 'Usage: ' + sys.argv[0] + ' [OPTIONS]' + """\n
Options:
   -f, --file       the file to use (stdin if no file given)
   -h, --help	    prints this 
   -v,--verbose	    be verbose (prints filename, other junk)
   -V,--version     prints just the version info and exits.
   
This expects to be unleashed on the result of running strings -el on a pd dump from windows process memory. Anything other than that, your mileage will certainly vary.\n
\n
"""	
	optlist, args = getopt.getopt(sys.argv[1:], 'vhbf:Vd', ['help','file=','version','verbose','debug'])
	#parse options.
	for o, a in optlist:
		if (o == '-h' or o == '--help'):
			print helpstr
			sys.exit()
		elif (o == '-v' or o == '--verbose'):
			options['verbose']=True			
		elif (o == '-d' or o == '--debug'):
			options['debug']=True
		elif (o == '-V' or o == '--version'):
			print "pdfbook version 2.0 Jeff Bryner"
			sys.exit()		
		else:	
			for option in options.keys():
				execcode = "if (o == '-%s' or o == '--%s'): options['%s'] = a" % (option[0], option, option)
				exec execcode

	return options


def gatherArtifacts():

	filedata=""
	recentactivities={}	#dict to hold recent activity entries. Stored in a python dict to eliminate dups.
	storymessages={}	#dict to hold story messages. Stored in a python dict to eliminate dups.
	fbookusers={}		#dict to hold facebook users that we run across. Store the ID and the name
	fbookowners={}		#dict to hold facebookIDs that have 'remove' buttons attached to stories..likely fbook account owners
	
	if options["verbose"]:
		print "FileName: %s " % options["file"]
	try:
		if options["file"]!='':
			fileHandle = open(options["file"], mode='r')
			fileHandle.close()
	except IOError:
		sys.stderr.write('Cannot open file\n')
		sys.exit(1)


   	 #read in the stdin/file 
    	if options["file"] != '':
        	fp = open(options['file'], 'r')
		filedata = fp.read()
		fp.seek(0)

	#look for stuff: 
#	try:
		while 1:
		        if options["file"] != '':
        		        line = safestring(fp.readline())
		        else:
	        	        line = safestring(sys.stdin.readline())
				#we're reading stdin. items may cross more than one line, so messily concat lines back into a filedata blob for use later.
				filedata +=line
		        if not line:
	        	    break
			    
			#find stuff that fits on one line at a time for easier regex processing

			fbookintentionalstories=fbookintentionalstoryre.findall(line)
			if len(fbookintentionalstories)>0:
				#we've got an 'intentionalstory' record that should look like this: 
				#UIIntentionalStory.setup($("div_story_50930182619061234_115316170123"), {"title":"Hide","unfollow":{"users":[{"id":543391123,"name":"Joe Facebook","firstName":"Joe","hideString":"Hide Joe"}]}});
				#Not much details, but names may help prove connections, and the ID's may come in handy later.
				for istory in fbookintentionalstories:
					try:
						matches = fbookintentionalstoryre.search(line)
						sys.stdout.write("Story from friend: id:" + matches.group(3) +': Name:' + matches.group(4) + '\n')
						#store the ID/name reference for later.
						if not fbookusers.has_key(matches.group(3)):
							fbookusers[matches.group(3)]=matches.group(4)
					except:
						sys.stderr.write("error handing intentional story in line: " + line.strip() + '\n')



			for fbookui in fbookuserinfosre.finditer(line):
				#we've got a 'userInfos' entry from the status update that should look like this: 
				#"userInfos":{"1421688012":{"name":"John Doe","firstName":"John","thumbSrc":"http:\/\/profile.ak.fbcdn.net\/v228\/472\/64\/q1421688012_3296.jpg","status":"StatusText goes here.","statusTime":1249259734,"statusTimeRel":"on Sunday","enableVC":false}}
				#group 1 is the whole thing, 2 is the userid, 3 is the name/value paring for the rest.
				#hey, it's almost in python dict format {"name":"value","name2":"value2"} ..lets munge the data and hope for the best.	
				fbookuidict=fbookui.group(3).replace('false',"'false'") #'false' by itself is no good. Python needs it in double quotes.
				fbookuidct=fbookuidict.replace('\\"','\"')	#javascript from fbook returns escaped quotes, this unescapes them.
				fbuiDictSource='{' + fbookuidict+'}'
				if options["debug"]:
					sys.stderr.write('debug: fbuiDictSource:' + fbuiDictSource + '\n')
				try:
					fbuiDict=dict(eval(fbuiDictSource))	#safe? conflicting stories abound on the intertubes....
					sys.stdout.write ('StatusUpdate: Name: %s thumbURL: %s status: %s statusTime: %s\n' %(fbuiDict['name'],fbuiDict['thumbSrc'].replace('\\',''),fbuiDict['status'],ctime(fbuiDict['statusTime'])))
					#store our userid we found
					if not fbookusers.has_key(fbookui.group(2)):
						fbookusers[fbookui.group(2)]=fbuiDict['name']
					
				except:
					sys.stderr.write("error handling fbookuserinfo: " + fbookui + '\n')
				
				

			fbookrecentactivity=fbookrecentactivityre.findall(line)
			if len(fbookrecentactivity)>0:
				#we've got a recent activity record that should look like this: 
				#<div class="UIRecentActivity_Body">Jeff became a fan of <a href="http://www.facebook.com/pages/Fishbone/6519219892?ref=mf" onclick='ft("4:9:47:1421688057:::6519219892:1:::s:1128129409718:");'>Fishbone</a>.<span class="UIActionLinks
				for activity in fbookrecentactivity:
					#dejunk it with browser specific stuff (onclicks, etc) 
					anactivity=printablestring(onclicksinglere.sub('',onclickre.sub('',activity)))
					#hash it and store it if it's one we haven't seen
					if not recentactivities.has_key(sha.new(anactivity.lower()).hexdigest()):
						recentactivities[sha.new(anactivity.lower()).hexdigest()]=anactivity
						if options['debug']:
							sys.stdout.write('debug: recentActivity:' + anactivity + '\n')
		
			
		#done with line by line proccessing
		#look for stuff that crosses lines

	
		#find storymessages, the stuff that shows up on your or other users walls
		#they look like this in html: 
		#<h3 class="UIIntentionalStory_Message"><span class="UIIntentionalStory_Names"><a href="http://www.facebook.com/profile.php?id=1421688057&amp;ref=mf" onclick='ft("4:9:22:1421688057::::0::::120397611385:");'>Jeff Bryner</a></span>webgoat..really webgoat is on my mind..glad you asked?</h3>
		#using regex groups and pythong finditer to get to them all
		#we'll hash them to weed out duplicates and store the results in a dictionary for later 
		#it's not fool proof as there's junk in memory that we can't always weed out, but it's better than repeated stories.
		for m in fbookintentionalstorymessagere.finditer(filedata):
			#substitute out all the cruft that don't mean much since we're not privy to fbook javascript though the obvious userid in the onlick looks tempting...
			amessage=spanendre.sub('',onclicksinglere.sub('',onclickre.sub('',m.group(1))))
			amessage=onmousedownre.sub('',amessage)
			amessage=onmousedownsinglere.sub('',amessage)
			amessage=printablestring(amessage)
			#hash and store it if it's new.
			if not storymessages.has_key(sha.new(amessage.lower()).hexdigest()):
				storymessages[sha.new(amessage.lower()).hexdigest()]=amessage
				#print "StoryMessage: " + spanendre.sub('',onclicksinglere.sub('',onclickre.sub('',m.group(1))))

		#10/2009 UI redesign changed the classes..so let's do it again
		for m in fbookgenericstorymessagere.finditer(filedata):
			#substitute out all the cruft that don't mean much since we're not privy to fbook javascript though the obvious userid in the onlick looks tempting...
			amessage=spanendre.sub('',onclicksinglere.sub('',onclickre.sub('',m.group(1))))
			amessage=onmousedownre.sub('',amessage)
			amessage=onmousedownsinglere.sub('',amessage)
			amessage=printablestring(amessage)			
			#hash and store it if it's new.
			if not storymessages.has_key(sha.new(amessage.lower()).hexdigest()):
				storymessages[sha.new(amessage.lower()).hexdigest()]=amessage
				#print "StoryMessage: " + spanendre.sub('',onclicksinglere.sub('',onclickre.sub('',m.group(1))))
		
		
		for m in fbookremovebuttonre.finditer(filedata):
			if not fbookowners.has_key(m.group(2)):
				fbookowners[m.group(2)]='owner'
			if options['debug']:
				sys.stderr.write('debug: removebutton' + m.group(0) +'\n')
				sys.stderr.write('debug: possibleOwner:' + m.group(2) + '\n')
		
		
		#emails?
		for m in fbookemailre.finditer(filedata):
			if options['debug']:
				sys.stderr.write('debug: FacebookEmail blob:' + m.group(1) + '\n' )
			for a in fbookemailauthorre.finditer(m.group(1)):
					sys.stdout.write('FacebookEmailDetail author: ' + a.group(2) + ' url: ' + a.group(1) + '\n' )
			for d in fbookemaildatere.finditer(m.group(1)):
					sys.stdout.write('FacebookEmailDetail Date: ' + printablestring(d.group(1)) + '\n' )
			for b in fbookemailbodyre.finditer(m.group(1)):
					sys.stdout.write('FacebookEmailDetail Body: ' + printablestring(b.group(1)) + '\n' )
		
		
		
#        except:
#		sys.stderr.write("Error handling line:" + line)
	#print the collection of unique recent activities
	for a in recentactivities:
		if options['verbose']:
			#print the hash of the item along with the item itself.
			sys.stdout.write('RecentActivity:'+ a + ':' +recentactivities[a] + '\n')
		else:
			sys.stdout.write('RecentActivity:' +recentactivities[a] + '\n')
	#print the collection of unique story messages
	for m in storymessages:
		if options['verbose']:
			#print the hash of the item along with the item itself.
			sys.stdout.write('StoryMessage:'+ m + ':' +storymessages[m] + '\n')
		else:
			sys.stdout.write('StoryMessage:' +storymessages[m] + '\n')
	
	#dump our repository of userids?
	if options['debug']:
		for userid in fbookusers:
			if fbookowners.has_key(userid):
				sys.stderr.write('FacebookUserID *owner*:' + userid + ':' + fbookusers[userid]+ '\n')
			else:
				sys.stderr.write('FacebookUserID:' + userid + ':' + fbookusers[userid]+ '\n')
	#see if we can figure out the likely owner of anything we found
	for userid in fbookusers:
		if fbookowners.has_key(userid):
			sys.stdout.write('Likely Owner of fbook memory artifacts: FacebookUserID:' + userid + ' Name:' + fbookusers[userid]+ '\n')
	
	
def main():
	global options
	options = parseOptions()
	gatherArtifacts()

if __name__ == '__main__':
  main()
