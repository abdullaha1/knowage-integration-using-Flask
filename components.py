import logging
import requests
import json
import pickle
from config import redis_client
import config as env


logger = logging.getLogger(__name__)


def check_permission(request):
    try:
        cookie = {'sessionid': request.cookies['sessionid']}
        session_id = 'session:'+request.cookies['sessionid']
        session_value = redis_client.get(session_id)
        pickled_object = pickle.loads(session_value)
        permission_objects = requests.get(env.scouting_url + "/api/scouting/knowage_permissions", cookies=cookie)
        permission_objects = json.loads(permission_objects.content)
        for permission_object in permission_objects["results"]:
            if permission_object["user"] == pickled_object['user_id']:
                return permission_object
        return False
    except Exception as e:
        logger.exception('Got exception when checking permission.')
        return False


def get_userid(sessionId):
    if len(sessionId) > 1:
        sessionId = sessionId.replace("=", ":").replace("sessionid", "session")
        if redis_client.exists(sessionId):
            sessionValue = redis_client.get(sessionId)
            pickledObject = pickle.loads(sessionValue)
            if 'user_id' in pickledObject:
                return pickledObject['user_id']
            else:
                return ''
        else:
            return ''

    else:
        return ''
