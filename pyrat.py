#! /usr/bin/python

#############################################################################
##                                                                         ##
## pyrat.py --- packet generator for interesting LL protocols              ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>         ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

    

import socket, sys, getopt, string, struct

def usage():
    print "Usage:...not ready yet"
    sys.exit(0)

if __name__ == "__main__":
    import code,sys,pickle,types,os
    import pyrat
    __builtins__.__dict__.update(pyrat.__dict__)

    SESSIONFILE="sessionfile"
    session=None
    session_name=""

    opts=getopt.getopt(sys.argv[1:], "hs:i:")
    iface = None
    try:
        for opt, parm in opts[0]:
	    if opt == "-h":
	        usage()
            elif opt == "-s":
                session_name = parm
            elif opt == "-i":
                iface = parm
        
	if len(opts[1]) > 0:
	    raise getopt.GetoptError("Too many parameters : [%s]" % string.join(opts[1]),None)


    except getopt.error, msg:
        print "ERROR:", msg
        sys.exit(1)


    if session_name:
        try:
            f=open(session_name)
            session=pickle.load(f)
            f.close()
            print "Using session [%s]" % session_name
        except IOError:
            print "New session [%s]" % session_name
        except EOFError:
            print "Error opening session [%s]" % session_name
        except AttributeError:
            print "Error opening session [%s]. Attribute missing" %  session_name

        if not session:
            session={SESSIONFILE: session_name}
    else:
        session={SESSIONFILE:""}

    if iface is not None:
        pass


    code.interact(banner = "Welcome to PyRat", local=session)

    if session.has_key("__builtins__"):
        del(session["__builtins__"])

    for k in session.keys():
        if type(session[k]) in [types.ClassType, types.ModuleType]:
             print "[%s] (%s) can't be saved. Deleted." % (k, type(session[k]))
             del(session[k])

    if session.has_key(SESSIONFILE) and session[SESSIONFILE]:
        try:
            os.rename(session[SESSIONFILE], session[SESSIONFILE]+".bak")
        except OSError:
            pass
        f=open(session[SESSIONFILE],"w")
        pickle.dump(session, f)
        f.close()
        
    sys.exit()


###########
## Consts
###########

ETHER_ANY = "\x00"*6
ETHER_BROADCAST = "\xff"*6

class param:
    iface="eth0"

###########
## Tools
###########


def sane(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r

def hexdump(x):
    x=str(x)
    l = len(x)
    for i in range(l):
        print "%02X" % ord(x[i]),
        if (i % 16 == 15):
            print " "+sane(x[i-15:i+1])
    if ((l%16) != 0): print "   "*(16-(l%16))+" "+sane(x[l-(l%16):])


def checksum(pkt):
    pkt=str(pkt)
    s=0
    if len(pkt) % 2 == 1:
        pkt += "\0"
    for i in range(len(pkt)/2):
        s = s +  (struct.unpack("!H",pkt[2*i:2*i+2])[0])
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return  ~s & 0xffff


###########
## Protos
###########

class ConstInstance(int):
    def __new__(cls, name, key, value):
        return int.__new__(cls,value)
    def __init__(self, name, key, value):
        int.__init__(self, value)
        self.__value = value
        self.__name = name
        self.__key = key
        self.__repr = name+"."+key
    def __repr__(self):
        return self.__repr
    def __eq__(self, other):
        return self.__repr == other.__repr__()
    def __hash__(self):
        return self.__repr.__hash__()


class ProtoEnumMetaClass:
    def __init__(self, name, bases, dict):
        self.__name__ = name
        self.__bases__= bases
        self.__dict = dict
        try:
            self.__consts = dict["consts"]
        except KeyError:
            self.__consts = {}
        for x,y in self.__consts.items():
            if type(y) is int:
                self.__consts[x] = ConstInstance(name, x, y)
    def __getattr__(self, attr):
        print "get", attr
        try:
            return self.__consts[attr]
        except KeyError:
            raise AttributeError, attr
        
    
        
ConstEnum=ProtoEnumMetaClass("ConstEnum", (), {"consts":{}})

class toto(ConstEnum):
    consts = {"tata":1}

class Packet:
    name=""
    types = {}
    fields = {"payload": ""}
    consts = {}
    underlayer = None
    payloadinfos = {}
    def __init__(self, **fields):
        self.fields=self.fields.copy()
        self.update(**fields)
    def update(self, **fields):
        self.fields.update(fields)
        self.str=self.build()
        if self.underlayer is not None:
            self.underlayer.update()
    def add_payload(self, payload):
        if isinstance(self.payload, Packet):
            self.payload.add_payload(payload)
        else:
            self.fields["payload"] = payload
            if isinstance(payload, Packet):
                payload.add_underlayer(self)
                self.payloadinfos = payload.get_infos(self)
            else:
                self.payloadinfos = {}
            self.update()
    def add_underlayer(self, underlayer):
        self.underlayer = underlayer
    def get_infos(self, underlayer):
        try:
            return self.types[underlayer.__class__]
        except KeyError:
            return {}
    def build(self):
        return str(self.payload)
    def copy(self):
        clone = self.__class__()
        clone.fields = self.fields.copy()
        clone.payloadinfos = self.payloadinfos
        if clone.fields.has_key("payload"):
            if isinstance(clone.payload, Packet):
                clone.fields["payload"] = clone.payload.copy()
                clone.payload.add_underlayer(clone)
        clone.update()
        return clone
    def __getattr__(self, attr):
        if self.fields.has_key(attr):
            a = self.fields[attr]
            if not a:
                if self.payloadinfos.has_key(attr):
                    a = self.payloadinfos[attr]
                elif attr == "len":
                    a=len(self.payload)
            return a
        elif self.consts.has_key(attr):
            return ConstInstance(self.name, attr, self.consts[attr])
        else:
            raise AttributeError, attr
    def __repr__(self):
        s = ""
        for k in self.fields.keys():
            s=s+" %s=%s" % (k, repr(self.__getattr__(k)))
        return "<Packet%s>"% s
    def __str__(self):
        return self.str
    def __add__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self.str+other
        else:
            return other.__radd__(self)
    def __radd__(self, other):
        if type(other) is str:
            return other+self.str
        else:
            raise TypeError
    def __len__(self):
        return len(self.str)



        
class Ether(Packet):
    name = "Ethernet"
    fields = { "src":  ETHER_ANY,
               "dst":  ETHER_BROADCAST,
               "type": 0x0000,
               "payload": ""}
    def build(self):
        return struct.pack("!6s6sH",
                           self.dst,
                           self.src,
                           self.type)+self.payload
    
Ether.types = { Ether: 0x0001 }

class DOT3(Packet):
    name = "802.3"
    fields = { "src":  ETHER_ANY,
               "dst":  ETHER_BROADCAST,
               "len":  0,
               "payload": ""}
    def build(self):
        return struct.pack("!6s6sH",
                           self.dst,
                           self.src,
                           self.len)+self.payload


class LLC(Packet):
    name = "LLC"
    fields = { "dsap":  0x00,
               "ssap":  0x00,
               "ctrl": 0,
               "type": 0x0000,
               "payload": ""}
    def build(self):
        return struct.pack("!BBB",
                           self.dsap,
                           self.ssap,
                           self.ctrl)+self.payload




class DOT1Q(Packet):
    name = "802.1Q"
    fields = { "prio": 0,
               "id":   0,
               "vlan": 1,
               "type": 0x0000,
               "payload": ""}
    def build(self):
        return struct.pack("!HH",
                           ( (self.prio << 13) |
                             (self.id << 12) |
                             self.vlan ),
                           self.type)+self.payload
DOT1Q.types = { Ether : { "type":0x8100 },
                DOT1Q : { "type":0x8100 } }



class STP(Packet):
    name = "Spanning Tree Protocol"
    fields = { "proto" : 0,
               "version" : 0,
               "bpdutype" : 0,
               "bpduflags" : 0,
               "rootid" : 0,
               "rootmac" : ETHER_ANY,
               "pathcost" : 0,
               "bridgeid" : 0,
               "bridgemac" : ETHER_ANY,
               "portid": 0,
               "age" : 1,
               "maxage" : 20,
               "hellotime" :  2,
               "fwddelay" : 15,
               "payload": ""}
    types = { LLC : { "dsap": 0x42 , "ssap" : 0x42 } }
    def build(self):
        return struct.pack("!HBBBH6sIH6sHHHHH",
                           self.proto,
                           self.version,
                           self.bpdutype,
                           self.bpduflags,
                           self.rootid,
                           self.rootmac,
                           self.pathcost,
                           self.bridgeid,
                           self.bridgemac,
                           self.portid,
                           int(256*self.age),
                           int(256*self.maxage),
                           int(256*self.hellotime),
                           int(256*self.fwddelay))+self.payload


class EAPOL(Packet):
    name = "EAPOL"
    fields = { "version": 1,
               "type": 0,
               "payload": ""}
    types = { Ether : { "type":0x888e },
              DOT1Q : { "type":0x888e } }
    EAP_PACKET= 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4
    def build(self):
        return struct.pack("!BBH",
                           self.version,
                           self.type,
                           len(self.payload))+self.payload
             

class EAP(Packet):
    name = "EAP"
    fields = { "code" : 1,
               "id" : 0,
               "type" : 0,
               "payload": ""}
    types = { EAPOL : { "type":EAPOL.EAP_PACKET } }
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    TYPE_ID = 1
    TYPE_MD5 = 4
    def build(self):
        if self.code in [self.SUCCESS, self.FAILURE]:
            return struct.pack("!BBH",
                               self.code,
                               self.id,
                               4)
        else:
            return struct.pack("!BBHB",
                               self.code,
                               self.id,
                               5+len(self.payload),
                               self.type)+self.payload
             

class ARP(Packet):
    name = "ARP"
    fields = { "op" : 1,
               "hwtype": 0x0001,
               "ptype":  0x0800,
               "hwlen":  6,
               "plen":   4,
               "hwsrc":  ETHER_ANY,
               "psrc":   "127.0.0.1",
               "hwdst":  ETHER_BROADCAST,
               "pdst":   "0.0.0.0",
               "payload:": ""}
    types = { Ether : { "type":0x0806 },
              DOT1Q : { "type":0x0806 } }
    consts = { "is_at": 2,
               "who_is": 1 }
    who_is = 1
    is_at = 2
    def build(self):
        return ( struct.pack("!HHBBH",
                             self.hwtype,
                             self.ptype,
                             self.hwlen,
                             self.plen,
                             self.op)
                 +self.hwsrc
                 +socket.inet_aton(self.psrc)
                 +self.hwdst
                 +socket.inet_aton(self.pdst) )






def send(x, iface=None, slp=-1):
    if iface is None:
        iface = param.iface
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((iface, 0))
    if slp >= 0:
        try:
            while 1:
                s.send(str(x))
                time.sleep(slp)
        except KeyboardInterrupt:
            pass
    else:
        s.send(str(x))
    s.close()
