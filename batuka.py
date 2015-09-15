import requests
import urllib
import json
import re
import os.path
import logging

sessionId = ''
config = ''

def initialize():
    global sessionId
    global config
    config = load_config()
    sessionId = execute_kanbanik_command({'commandName':'login','userName': config['kanbanik']['user'] ,'password': config['kanbanik']['password']})['sessionId']

def load_config():
    with open('/etc/batuka/config.json') as data_file:
        return json.load(data_file)

def execute_kanbanik_command(json_data):
    OK_STATUS = 200
    ERROR_STATUS= 452
    USER_NOT_LOGGED_IN_STATUS = 453

    url = config['kanbanik']['url']
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

    resp = requests.post(url, data='command='+json.dumps(json_data), headers=headers)
    if resp.status_code == OK_STATUS:
        res = ''
        try:
            res = resp.json()
        except TypeError:
            res = resp.json
        return res

    if resp.status_code == ERROR_STATUS or resp.status_code == USER_NOT_LOGGED_IN_STATUS:
        logging.error("error while calling kanbanik")
        logging.error("response: " + str(resp.status_code))
        logging.error("request: " + str(json_data))
        return None

def load_data_from_kanbanik():
    return execute_kanbanik_command({'commandName':'getTasks','includeDescription':True,'sessionId': sessionId})['values']

def load_data_from_bz(config_loader = load_config):
    return execute_bz_query(config['bugzilla']['loadAllQuery'])

def execute_bz_query(query):
    try:
        bz = config['bugzilla']
        url = bz['url']
        headers = {'Content-Type': 'application/json', 'Accpet': 'application/json'}
        raw = requests.post(url, data=json.dumps(query), headers=headers)
        return raw.json()
    except:
        logging.error("error while calling bugzilla")
        logging.error("request: " + str(query))
        logging.error("response: " + str(raw))


# expects a function returning a list of all bugzilla tasks
# returns the same list of tasks formatted as:
# ((BZ_ID, BZ_TIMESTAMP), THE_BZ)
def bz_as_map(bz_loader = load_data_from_bz):
    return [((str(bz['id']), bz['last_change_time'], bz['target_release']), bz) for bz in bz_loader()['result']['bugs']]

# expects a function returning a list of all kanbanik tasks
# returns a list of tasks imported from bugzilla (e.g. managed by this script) in a form of:
# ((BZ_ID, BZ_TIMESTAMP, TICKET_ID), THE_WHOLE_TASK)
def kanbanik_as_map(task_loader = load_data_from_kanbanik):
    all_tasks = [(parse_metadata_from_kanbanik(task.get('description', '')), task) for task in task_loader()]
    return filter(lambda x: x[0] != ('', '', ''), all_tasks)

def parse_metadata_from_kanbanik(text):
    matchObj = re.match( r'.*\$BZ;(.*);TIMESTAMP;(.*)\$\$target-release(.*)\$.*', text, re.S|re.I)
    if matchObj:
        return (matchObj.group(1), matchObj.group(2), matchObj.group(3))
    else:
        return ('', '', '')

def bz_to_kanbanik(bz):
    res = {
       'commandName': 'createTask',
       'name': bz[1]['summary'],
       'description': u'$COMMENT' + bz[1]['comments'] + '$COMMENT$BZ;' + bz[0][0] + ';TIMESTAMP;'  + bz[0][1] + '$' + '$target-release' + ','.join(bz[0][2]) + '$',
       'workflowitemId': workflowitem_id_from_bz(bz[1]['status'], None),
       'version':1,
       'projectId': config['kanbanik']['projectId'],
       'boardId': config['kanbanik']['boardId'],
       'sessionId': sessionId,
       'order': 0
    }

    add_assignee(res, bz[1])
    add_tags(res, bz[1])
    add_class_of_service(res, bz[1])


    return res

def update_bz_to_kanbanik(kanbanik, bz):
    edit = kanbanik[1].copy()

    edit['description'] = replace_timestamp(edit, bz[0][1])
    edit['description'] = replace_target_release(edit, ','.join(bz[0][2]))
    edit['description'] = replace_comment(edit, bz[1]['comments'])
    edit['description'] = sanitize_string(edit['description'])
    edit['commandName'] = 'editTask'
    edit['sessionId'] = sessionId

    add_assignee(edit, bz[1])
    add_tags(edit, bz[1])
    add_class_of_service(edit, bz[1])
    res = [edit]

    move = edit.copy()
    result_status = workflowitem_id_from_bz(bz[1]['status'], move['workflowitemId'])

    if move['workflowitemId'] != result_status:
        move['workflowitemId'] = result_status
        move['version'] = move['version'] + 1
        move['description'] = ''
        add_assignee(move, bz[1])
        add_tags(move, bz[1])
        add_class_of_service(move, bz[1])
        res.append({
            'commandName': 'moveTask',
            'task': move,
            'sessionId': sessionId
        })

    return res


def add_class_of_service(kanbanik, bz):
    class_of_service_mapping = config['bz2kanbanikMappings']['prioritySeverity2classOfServiceId']
    priority = bz['priority']
    severity = bz['severity']
    specific = priority + '_' + severity
    more_generic = priority + '_*'
    res = class_of_service_mapping['*']
    if specific in class_of_service_mapping:
        res = class_of_service_mapping[specific]
    elif more_generic in class_of_service_mapping:
        res = class_of_service_mapping[more_generic]

    kanbanik['classOfService'] = {'id': res, 'name': 'fake', 'description': 'fake', 'colour': 'fake', 'version': 1}


def add_tags(kanbanik, bz):
    url = re.sub(r'/jsonrpc.cgi', '/show_bug.cgi?id=' + str(bz['id']), config['bugzilla']['url'])
    bz_link = {'name': 'B', 'description': 'BZ Link', 'onClickUrl': url, 'onClickTarget': 1, 'colour': 'green'}
    tags = [bz_link]
    if 'target_release' in bz:
        tr = bz['target_release']
        tr_tag = {'name': 'TR: ' + ''.join(tr), 'description': 'Target Release', 'colour': 'green'}
        tags = [bz_link, tr_tag]

    kanbanik['taskTags'] = tags


def add_assignee(kanbanik, bz):
    user_mapping = config['bz2kanbanikMappings']['user2kanbanikUser']
    userName = user_mapping['unknown']

    if bz['assigned_to'] in user_mapping:
        userName = user_mapping[bz['assigned_to']]

    kanbanik['assignee'] = {'userName': userName, 'realName': 'fake', 'pictureUrl': 'fake', 'sessionId': 'fake', 'version': 1}

def workflowitem_id_from_bz(bz_status, current_workflowitem):
    status_mapping = config['bz2kanbanikMappings']['status2workflowitem']
    prohibited_moves = config['bz2kanbanikMappings']['prohibitedTransitions']
    result_status = config['kanbanik']['backlogWorkflowitemId']
    if bz_status in status_mapping:
        proposed_status = status_mapping[bz_status]
        if current_workflowitem is not None and current_workflowitem in prohibited_moves and proposed_status in prohibited_moves[current_workflowitem]:
            result_status = current_workflowitem
        else:
            result_status = proposed_status

    return result_status

def replace_target_release(kanbanik, target_release):
    return re.sub(r'\$target-release.*\$', '$target-release' + target_release + '$', kanbanik['description'])

def replace_timestamp(kanbanik, timestamp):
    return re.sub(r'\;TIMESTAMP;.*\$\$', ';TIMESTAMP;' + timestamp + '$$', kanbanik['description'])

def replace_comment(kanbanik, comment):
    return re.sub(r'\$COMMENT.*COMMENT\$', '$COMMENT'+ comment +'COMMENT$', kanbanik['description'])

def create_tasks_to_add(kanbanik_map, bz_map, bz_to_kanbanik_converter = bz_to_kanbanik):
    to_enrich= [bz for bz in bz_map if bz[0][0] not in [kanbanik_task[0][0] for kanbanik_task in kanbanik_map]]
    return [bz_to_kanbanik_converter(bz) for bz in enrich_bzs(to_enrich)]

def create_tasks_to_move_to_unknown(kanbanik_map, bz_map):
    return [move_kanbanik_to_unknown(kanbanik_task) for kanbanik_task in kanbanik_map if kanbanik_task[0][0] not in [bz[0][0] for bz in bz_map]]

def move_kanbanik_to_unknown(kanbanik):
    kanbanik[1]['workflowitemId'] = config['kanbanik']['unknownWorkflowitemId']
    kanbanik[1]['version'] = kanbanik[1]['version'] + 1
    kanbanik[1]['description'] = ''
    return {
        'commandName': 'moveTask',
        'task': kanbanik[1],
        'sessionId': sessionId
    }

def enrich_bzs(to_enrich):
    if len(to_enrich) == 0:
        return to_enrich

    bz_config = config['bugzilla']
    bz_config['loadCommentsQuery']['params'][0]['ids'] = [bz[1]['id'] for bz in to_enrich]
    all_comments = execute_bz_query(bz_config['loadCommentsQuery'])

    for bz in to_enrich:
        if str(bz[1]['id']) in all_comments['result']['bugs']:
            bz_comments = "".join([bz_comment_to_kanbanik_comment(comment) for comment in all_comments['result']['bugs'][str(bz[1]['id'])]['comments']])
            bz[1]['comments'] = bz_comments

    return to_enrich

def bz_comment_to_kanbanik_comment(bz_comment):
    bz_comment['text'] = sanitize_string(bz_comment['text'])
    return '<br><b>' + bz_comment['author'] + '</b> Time: ' + bz_comment['creation_time'] + '<br>' + bz_comment['text'] + '<hr>'

def sanitize_string(s):
    without_non_ascii = "".join(i for i in s if ord(i)<128)
    with_correct_enters = "<br>".join(without_non_ascii.split("\n"))
    without_json_special_chars = re.sub(r'"', '\'', with_correct_enters)
    return urllib.quote_plus(without_json_special_chars)

def create_tasks_to_modify(kanbanik_map, bz_map, force_update, kanbanik_task_from_bz_updater = update_bz_to_kanbanik):
    bzs = []
    for bz in bz_map:
        for kanbanik_task in kanbanik_map:
            if bz[0][0] == kanbanik_task[0][0] and ((bz[0][1] != kanbanik_task[0][1] or ",".join(bz[0][2]) != kanbanik_task[0][2]) or force_update):
               bzs.append(bz)

    res = []
    for bz in enrich_bzs(bzs):
        for kanbanik_task in kanbanik_map:
            if bz[0][0] == kanbanik_task[0][0] and ((bz[0][1] != kanbanik_task[0][1] or ",".join(bz[0][2]) != kanbanik_task[0][2]) or force_update):
                res.append(kanbanik_task_from_bz_updater(kanbanik_task, bz))

    return res

def process():
    initialize()

    try:
        kanbanik_map = kanbanik_as_map()
        bz_map = bz_as_map()
        for task_to_add in create_tasks_to_add(kanbanik_map, bz_map):
            execute_kanbanik_command(task_to_add)

        for tasks_to_modify in create_tasks_to_modify(kanbanik_map, bz_map, True):
            for task_to_modify in tasks_to_modify:
                execute_kanbanik_command(task_to_modify)

        for unknow_task in create_tasks_to_move_to_unknown(kanbanik_map, bz_map):
            execute_kanbanik_command(unknow_task)

    finally:
        execute_kanbanik_command({'commandName':'logout','sessionId': sessionId})

if __name__ == "__main__":
    logging.basicConfig(filename='/var/log/batuka.log',level=logging.DEBUG)
    logging.info("batuka started")

    lock_file_path = '/tmp/batuka.lock'
    if not os.path.isfile(lock_file_path):
        open(lock_file_path, 'w+')
    else:
        msg = "The lock file already exists at " + lock_file_path + ' - if you are sure no other instance of batuka is running, please delete it and run batuka again.'
        logging.error(msg)
        raise Exception(msg)

    try:
        logging.info("going to process")
        process()
        logging.info("process ended successfully")
    finally:
        os.remove(lock_file_path)