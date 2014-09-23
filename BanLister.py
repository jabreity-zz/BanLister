import SocketServer
import re
import os
from netaddr import IPNetwork, IPAddress

from datetime import datetime

# Pattern to detect IP addresses in Syslogd messages
ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


def AddIP(IpAddress):
    #Open the banlist.txt file, and write it out.  From here we use
    #Once you have written out the banlist, Aclizer applies the list
    #to the edge routers.  We keep 2 copies of banlist, one in 
    #a production spot, and one in a failover spot, accessed
    #via a network share.
    with open(r"C:\banlister\banlist.txt", "a") as g:
        #Append the IP address specified to the banlist.
        print >> g, str(IpAddress)
        print "Logged to banlist.txt: " + str(IpAddress)

    #And open our failover hosting location, and write it out.
    with open(r"Z:\banlist.html", "a") as g:
        #Append the IP address specified to the banlist.
        print >> g, str(IpAddress)
        print "Logged to Z:\banlist.txt: " + str(IpAddress)


def CheckBanList(IpAddress):
    #Validate that the IP is not in the banlist.  If it is,
    #evaluate to true, and prevent the extraneous entry.
    with open(r"C:\banlister\banlist.txt", "r") as h:
        for x in h:

            #Remove garbage, and null lines
            if x.strip() == "": continue

            #Compare IP Provided to each line of the banlist
            if x.strip() == IpAddress:
                return 1
        return 0


def CheckExclusionList(IpAddress):
    #Create a list of excluded networks using slash notation.
    #For example, 10.0.0.0/8 is a thing, and 192.168.1.0/24 is too.
    #This will prevent the ip addresses in that subnet from being banned
    #and with note the IP as Local in the console accordingly..
    with open(r"C:\banlister\excludelist.txt", "r") as f:

        #Iterate over file line by line, and compare.
        for x in f:

            #Remove garbage, and null lines
            if x.strip() == "": continue

            #compare IP provided to the networks in exclusion list txt file
            if IPAddress(str(IpAddress)) in IPNetwork(x):
                return 1
    return 0


def LogPacket(data):
    #It always makes me happy when logfiles are named yyyy/mm/dd
    #with dd being the file name.  Easy to search/use.

    #set a variable with the current time
    now = datetime.now()

    #establish a root path
    path = "C:\\banlister\\" + str(now.year) + "\\" + str(now.month)

    #if folder's path does not exist, make it so.
    filename = path + "\\" + str(now.day)
    if not os.path.exists(path):
        os.makedirs(path)

    #After the file creation is managed, write raw packet
    #to the logfile we just made a path for.
    with open(filename, "a") as j:
        print >> j, str(data)
        print "Logged Packet to " + str(filename)


class MyUDPHandler(SocketServer.BaseRequestHandler):
    """
    self.request consists of a pair of data and client socket
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]

        #Log the inbound UDP IP src of packet to console
        print "{} wrote:".format(self.client_address[0])

        #Print raw data for debugging fun
        print data

        #Print on the IP addresses found in each log entry that match the IP pattern
        findIP = re.findall(ipPattern, data)
        print findIP

        #Check the exclusion list, and if not excluded and not banned, ban.
        for i in findIP:

            #CheckExclusionList Returns a 1 if the list
            #turns up a match on the IP address provided.
            if CheckExclusionList(i):

                #The IP address provided matched the exclusion list,
                #so do not ban it, but notify the console.
                print "Local IP: " + str(i)

            #Otherwise, if the IP is not on the local IP exclusion list
            #check the banlist, and ban if not noted
            else:

                #CheckBanList returns 1 if it finds a match in the banlist
                #This is expected to happen often!
                #There is an opportunity to see more samples 
                #of the offending traffic hit the firewall
                #before the Aclizer script kicks off and denys the traffic
                #on the edge(every 5 mins polling the banlist.txt)
                if CheckBanList(i) == 1:

                    #Remember, this is expected, and just means you already
                    #have logged a sample of the traffic, and it's in the banlist
                    print "External IP: " + str(i) + " Already Banned"

                #Otherwise, ban the traffic, and log the raw packet 
                #as a sample of the offending traffic.
                elif CheckBanList(i) == 0:
                    AddIP(i)
                    LogPacket(data)
                    print "External IP: " + str(i) + " Banned"


if __name__ == "__main__":
    #Specify the local IP Address if nessecary, and
    #port number to listen for inbound syslog messages.
    HOST, PORT = "localhost", 11514

    #Start your engines!
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)

    #Don't stop!
    server.serve_forever()
__author__ = 'JAB'
