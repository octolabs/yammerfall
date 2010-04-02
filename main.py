#!/usr/bin/env python

import os
import logging
import urllib
from time import time
from random import getrandbits
from google.appengine.api import urlfetch
from google.appengine.ext.webapp import RequestHandler, WSGIApplication, template, wsgiref
from django.utils import simplejson

from yammerConfig import CONSUMER_KEY, CONSUMER_SECRET

REQUEST_TOKEN_URL = 'https://www.yammer.com/oauth/request_token'
ACCESS_TOKEN_URL = 'https://www.yammer.com/oauth/access_token'
USER_AUTH_URL = 'https://www.yammer.com/oauth/authorize'
DEFAULT_API_PREFIX = 'https://www.yammer.com/api/v1/'
DEFAULT_API_SUFFIX = '.json'

HEADERS = {
	'Content-Type': 'application/x-www-form-urlencoded',
	'Accept': '*/*',
	'Accept-Language': 'en-us',
	'Accept-Encoding': 'gzip, deflate',
	'Connection': 'keep-alive',
}

def getOAuthHeaders(token=None, token_secret='', verifier=None):
	OAuthHeaders = 'OAuth realm=""'
	OAuthHeaders += ', oauth_consumer_key="%s"' % CONSUMER_KEY
	
	if token:
		OAuthHeaders += ', oauth_token="%s"' % token
	
	OAuthHeaders += ', oauth_signature_method="PLAINTEXT"'
	OAuthHeaders += ', oauth_signature="%s%%26%s"' % (CONSUMER_SECRET, token_secret)
	currentTime = int(time())
	OAuthHeaders += ', oauth_timestamp="%s"' % currentTime
	OAuthHeaders += ', oauth_nonce="%s"' % currentTime
	
	if verifier:
		OAuthHeaders += ', oauth_verifier="%s"' % verifier
	
	OAuthHeaders += ', oauth_version="1.0"'
	return str(OAuthHeaders)

class MainHandler(RequestHandler):

	def get_cookie(self):
		return self.request.cookies.get('oauth.yammerfall', '')
	
	def set_cookie(self, value, path='/'):
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; path=%s; expires="Fri, 31-Dec-2021 23:59:59 GMT"' %
			('oauth.yammerfall', value, path)
			)
	
	def expire_cookie(self, path='/'):
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=; path=%s; expires="Fri, 31-Dec-1999 23:59:59 GMT"' %
			('oauth.yammerfall', path)
			)
	
	def get(self):
		
		if self.request.get('expire_cookie', None) == 'now':
			logging.debug('EXPIRING COOKIE')
			self.expire_cookie()
			self.redirect('/')
			return
		
		if self.get_cookie():
			logging.debug('GOT COOKIE! %s' % self.get_cookie())
			template_values = {
				'messagesUrl': '/messages?%s' % self.get_cookie(),
			}
			path = os.path.join(os.path.dirname(__file__), "templates/home.html")
			self.response.out.write(template.render(path, template_values))
			return
		
		logging.debug('NO COOKIE!')
		
		HEADERS['Authorization'] = getOAuthHeaders()
		result = urlfetch.fetch(
			url=REQUEST_TOKEN_URL,
			payload='',
			method=urlfetch.POST,
			headers=HEADERS,
		)
		
		data = {}
		for nv in result.content.split('&'):
			(n, v) = nv.split('=')
			data[n] = v
		
		template_values = {
			'user_auth_url': USER_AUTH_URL,
			'oauth_token': data['oauth_token'],
			'oauth_token_secret': data['oauth_token_secret'],
		}
		path = os.path.join(os.path.dirname(__file__), "templates/login.html")
		self.response.out.write(template.render(path, template_values))
		return
		
		
		
	def post(self):
		
		logging.debug('AUTHORIZE WITH VERIFY CODE: %s' % self.request.get('oauth_verifier'))
		
		HEADERS['Authorization'] = getOAuthHeaders(
			token = self.request.get('oauth_token'), 
			token_secret = self.request.get('oauth_token_secret'),
			verifier = self.request.get('oauth_verifier'))

		result = urlfetch.fetch(
			url=ACCESS_TOKEN_URL,
			method=urlfetch.POST,
			headers=HEADERS,
		)
		
		logging.debug('AUTHORIZED: %s' % result.content)
		
		self.set_cookie(result.content)
		self.redirect('/')
		

class MessagesHandler(RequestHandler):
	def get(self):

		HEADERS['Authorization'] = getOAuthHeaders(
			token = self.request.get('oauth_token'), 
			token_secret = self.request.get('oauth_token_secret'))
		MSGS_URL = '%smessages%s' % (DEFAULT_API_PREFIX, DEFAULT_API_SUFFIX)
		
		result = urlfetch.fetch(
			url=MSGS_URL,
			method=urlfetch.GET,
			headers=HEADERS,
		)
		
		data = simplejson.loads(result.content)
		
		#self.response.out.write(data)
		
		users = {}
		ref_msgs = {}
		for r in data['references']:
			if r['type'] == 'user':
				users[r['id']] = r
				users[r['name']] = r
			elif r['type'] == 'message':
				ref_msgs[r['id']] = r
				
		for m in data['messages']:
			m['mugshot_url'] = users[m['sender_id']]['mugshot_url']
			m['full_name'] = users[m['sender_id']]['full_name']
			m['like_list'] = []
			if m['liked_by']['count'] > 0:
				for liked_by_name in m['liked_by']['names']:
					try:
						m['like_list'].append((liked_by_name['full_name'], users[liked_by_name['permalink']]['mugshot_url']))
					except:
						pass
			if m['replied_to_id']:
				in_reply_to = users[ref_msgs[m['replied_to_id']]['sender_id']]
				m['in_reply_to'] = (in_reply_to['full_name'], in_reply_to['mugshot_url'])
		
		template_values = {
			'messages' : data['messages'],
		}
		path = os.path.join(os.path.dirname(__file__), "templates/messagelist.html")
		self.response.out.write(template.render(path, template_values))


# ------------------------------------------------------------------------------
# self runner -- gae cached main() function
# ------------------------------------------------------------------------------

def main():
	logging.getLogger().setLevel(logging.DEBUG)
	application = WSGIApplication([
		('/', MainHandler),
		('/messages', MessagesHandler),
	   ], debug=True)
	
	wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
	main()