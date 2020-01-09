from flask import Flask, Blueprint,request, redirect, make_response, Response,session
import requests
import json
import os,sys
import config
from config import redis_client
import pickle
import logging
import json_log_formatter
import config as env
import components
from datetime import datetime
import traceback
app = Flask(__name__)
session_request = requests.Session()


class CustomisedJSONFormatter(json_log_formatter.JSONFormatter):
    def json_record(self, message, extra, record):
        extra['type'] = 'WEB'
        extra['message'] = message
        extra['time'] = datetime.now()
        extra['level'] = logging.getLevelName(logger.getEffectiveLevel())
        extra['line'] = record.lineno
        extra['pathname'] = record.pathname
        extra['func_name'] = record.funcName
        if sys.exc_info():
            extra['traceback'] = traceback.format_exc().split("\n")
        return extra

    def to_json(self, record):
        return self.json_lib.dumps(record, indent=' ')

formatter = CustomisedJSONFormatter()
logfile = os.path.join(env.logdir, "knowage_service.log")
logger = logging.getLogger("knowage")
logger.setLevel(logging.WARNING)

file_handler = logging.FileHandler(logfile, 'a', 'utf-8')
file_handler.setLevel(logging.WARNING)
# file_format = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d in %(funcName)s]')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
app.logger.addHandler(file_handler)
#
#

@app.after_request
def after_request(response):
    sessionid = request.headers.get('Cookie', ' ').split('=')[-1]
    logger.warning(
        "server error",
        extra={
            'method': request.method,
            'application': 'knowage',
            'url_path': request.path,
            'session_id': sessionid,
            'user_id': components.get_userid(request.headers.get('Cookie', ' '))
        })
    return response


def login_request(username, password):
    request_data = session_request.post(
        request.base_url+'knowage/servlet/AdapterHTTP?PAGE=LoginPage&NEW_SESSION=TRUE',
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'from': 'knowage'},
        data={'userID': username, 'password': password, 'isInternalSecurity': 'true'}, json=None)
    response_headers = {
        "Location": request.base_url + "knowage/servlet/AdapterHTTP?PAGE=LoginPage&NEW_SESSION=TRUE",
        "Content-Type": "application/x-www-form-urlencoded",
        "from": "knowage"
    }
    response = Response(status=302, content_type='text/html', headers=response_headers)
    response.set_cookie('JSESSIONID', request_data.cookies.get('JSESSIONID', ''), path='/knowage/')
    return response


@app.route("/")
def knowage_login():
    try:
        sessionid = request.headers.get('Cookie', ' ')
        session_id = 'session:' + request.cookies['sessionid']
        session_value = redis_client.get(session_id)
        pickled_object = pickle.loads(session_value)
        ## login check for engro user
        if 'sessionid' in sessionid:
            if pickled_object['user_id']:
                object = components.check_permission(request)
                ## knowage user check
                if object:
                    ## knowage user type check
                    if object["user_type"] == 'admin':
                        return login_request('demo_admin', 'demo_admin')
                    elif object['user_type'] == 'manager':
                        return login_request('demo_manager', 'demo_manager')
                    else:
                        return login_request('demo_user', 'demo_user')
                else:
                    return json.dumps({"status_code": 200, "message": "User not permitted"})
            else:
                return json.dumps({"status_code": 200, "message": "Your session has expired. Please Login again"})
        else:
            return json.dumps({"status_code": 200, "message": "User not logged in"})
    except ValueError as e:
        print(e)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8282)
