import datetime
import os
import json
import traceback
from rauth import OAuth2Service
from datetime import timezone, datetime


class KSTOauth2Service:

    token_received_time = 0
    raw_token = ''
    
    def __init__(self,token_name, client_id,client_secret,access_token_url,redirect_uri,api_key):
        self._token_name=token_name
        self._client_id=client_id
        self._client_secret=client_secret
        self._access_token_url=access_token_url
        self._api_key = api_key
        self._redirect_uri = redirect_uri

    
    def get_service(self):
        service = OAuth2Service(
               name=self._token_name,
               client_id=self._client_id,
               client_secret=self._client_secret,
               access_token_url=self._access_token_url
               )
        return service
        

    def is_token_active(self):
        if int(datetime.now(tz=timezone.utc).timestamp())  < self.token_received_time:
            return True
        else:
            return False

    def get_token_refresh_session(self):
        
        service = self.get_service()
        
        raw_token = service.get_raw_access_token(data = {"code": 'code',"redirect_uri": self._redirect_uri, "grant_type": "client_credentials"})
        json_token = json.loads(raw_token.text)
        self.token_received_time =  int(datetime.now(tz=timezone.utc).timestamp()) + json_token['expires_in']
        session = service.get_session(json_token['access_token'])
        return session

    
    def post_response(self,query_url,body):
        self.initialize_token()

        if self.is_token_active():
            json_token = json.loads(self.raw_token.text)
            service = self.get_service()
            session = service.get_session(json_token['access_token'])
            _header = {"X-API-KEY": self._api_key, "Content-type": "application/json"}
            response = session.post(query_url,data=body,headers=_header)
        
            if response.status_code == 401:
                json_response = json.loads(response.text)
                if 'message' in json_response:
                    if json_response['message'] == 'The incoming token has expired':
                        session = self.get_token_refresh_session()
                        response = session.post(query_url,data=body,headers=_header)
                        return response.content.decode('utf-8')
            else:
                if response.status_code ==200:
                    return response.content.decode('utf-8')
        else:
            session = self.get_token_refresh_session()
            response = session.post(query_url,data=body,headers=_header)
            return response.content.decode('utf-8')

    def get_response(self,query_url,Params =None):
        self.initialize_token()

        if self.is_token_active():
            json_token = json.loads(self.raw_token.text)
            service = self.get_service()
            session = service.get_session(json_token['access_token'])
            response = session.get(query_url,
                        params=Params,
                        headers={'X-API-KEY': self._api_key})
        
            if response.status_code == 401:
                json_response = json.loads(response.text)
                if 'message' in json_response:
                    if json_response['message'] == 'The incoming token has expired':
                        session = self.get_token_refresh_session()
                        
                        response = session.get(query_url,
                        params=Params,
                        headers={'X-API-KEY': self._api_key})
                        return response.content.decode('utf-8')
            else:
                if response.status_code ==200:
                    return response.content.decode('utf-8')
        else:
            session = self.get_token_refresh_session()
            response = session.get(query_url,
                        params=Params,
                        headers={'X-API-KEY': self._api_key})
            return response.content.decode('utf-8')

    def initialize_token(self):
        if self.raw_token == '':
            service = self.get_service()
            self.raw_token = service.get_raw_access_token(data = {"code": 'code',"redirect_uri": self._redirect_uri, "grant_type": "client_credentials"})
            json_token = json.loads(self.raw_token.text)
            self.token_received_time =  int(datetime.now(tz=timezone.utc).timestamp()) + json_token['expires_in']
        





    