import requests
import urllib
import json
import re
import os.path
import logging
import sys
import getopt

sessionId = ''
config = ''


def initialize(kanbanik_pass):
    global sessionId
    global config
    config = load_config()
    if kanbanik_pass is not None:
        config['kanbanik']['password'] = kanbanik_pass

    sessionId = execute_kanbanik_command({'commandName': 'login', 'userName': config['kanbanik']['user'], 'password': config['kanbanik']['password']})['sessionId']

def load_config():
    with open('/etc/batuka.json') as data_file:
        return json.load(data_file)

def execute_kanbanik_command(json_data):
    OK_STATUS = 200
    ERROR_STATUS= 452
    USER_NOT_LOGGED_IN_STATUS = 453

    url = config['kanbanik']['url']
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

    resp = requests.post(url, data='command='+json.dumps(json_data), headers=headers)
    if resp.status_code == OK_STATUS:
        try:
            return resp.json()
        except TypeError:
            return resp.json
        return ''

    if resp.status_code == ERROR_STATUS or resp.status_code == USER_NOT_LOGGED_IN_STATUS:
        logging.error("error while calling kanbanik")
        logging.error("response: " + str(resp.status_code))
        logging.error("request: " + str(json_data))
        return None

def add_bz_pr_tags(task, web_url, api_url):
    radar_tag = {'name': 'bzradar', 'description': '', 'onClickUrl': web_url, 'onClickTarget': 1, 'colour': 'orange'}
    xgh_tag = {'name': 'xbz:' + api_url, 'description': api_url, 'onClickUrl': web_url, 'onClickTarget': 1, 'colour': 'silver'}
    tags = [radar_tag, xgh_tag]

    task['taskTags'] = tags


def add_gh_pr_tags(task, web_url, api_url):
    radar_tag = {'name': 'ghradar', 'description': '', 'onClickUrl': web_url, 'onClickTarget': 1, 'colour': 'silver'}
    xgh_tag = {'name': 'xgh', 'description': api_url, 'onClickUrl': web_url, 'onClickTarget': 1, 'colour': 'silver'}
    tags = [radar_tag, xgh_tag]

    task['taskTags'] = tags


def create_task_to_add(add_tags, web_url, api_url):
    res = {
        'commandName': 'createTask',
        'name': 'added to radar',
        'description': 'd',
        'workflowitemId': config['kanbanik']['backlogWorkflowitemId'],
        'version': 1,
        'projectId': config['bz2kanbanikMappings']['userSpecificMappings']['unknown']['projectId'],
        'boardId': config['kanbanik']['boardId'],
        'sessionId': sessionId,
        'order': 0
    }

    add_tags(res, web_url, api_url)
    res['assignee'] = {'userName': config['bz2kanbanikMappings']['userSpecificMappings']['unknown']['kanbanikName'], 'realName': 'fake', 'pictureUrl': 'fake', 'sessionId': 'fake', 'version': 1}

    class_of_service = config['bz2kanbanikMappings']['prioritySeverity2classOfServiceId']['*']
    res['classOfService'] = {'id': class_of_service, 'name': 'fake', 'description': 'fake', 'colour': 'fake', 'version': 1}
    return res


def process(kanbanik_pass, web_url):
    initialize(kanbanik_pass)

    try:
        if web_url is None:
            return

        match_obj = re.match(r'https://github.com/(.*)/(.*)/pull/(.*)$', web_url, re.S | re.I)
        if match_obj:
            # github pull request
            api_url = "https://api.github.com/repos/" + match_obj.group(1) + "/" + match_obj.group(2) + "/pulls/" + match_obj.group(3)
            to_add = create_task_to_add(
                add_gh_pr_tags,
                web_url,
                api_url)
            execute_kanbanik_command(to_add)

        if (web_url.startswith("https://bugzilla")):
            # bugzilla bug
            id_option = web_url.find("?id=")
            api_url = None
            if id_option != -1:
                api_url = web_url[web_url.find("?id=") + 4:]
            else:
                api_url = web_url[web_url.rfind('/') + 1:]

            to_add = create_task_to_add(
                add_bz_pr_tags,
                web_url,
                api_url)
            execute_kanbanik_command(to_add)
    finally:
        execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})

if __name__ == "__main__":
    kanbanik_pass = None
    url = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hk:u", ["kanbanikpass=", "url="])
    except getopt.GetoptError:
        print 'addtoradar.py -k <kanbanik password>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'batuka.py -k <kanbanik password>'
            sys.exit()
        elif opt in ("-k", "--kanbanikpass"):
            kanbanik_pass = arg
        elif opt in ("-u", "--url"):
            url = arg

    process(kanbanik_pass, url)
