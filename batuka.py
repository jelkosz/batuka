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

def initialize(bz_pass, kanbanik_pass):
    global sessionId
    global config
    config = load_config()
    if kanbanik_pass is not None:
        config['kanbanik']['password'] = kanbanik_pass

    if bz_pass is not None:
        config['bugzilla']['loadAllQuery']['params'][0]['Bugzilla_password'] = bz_pass
        config['bugzilla']['loadCommentsQuery']['params'][0]['Bugzilla_password'] = bz_pass
        config['bugzilla']['loadSpecificBugs']['params'][0]['Bugzilla_password'] = bz_pass

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


def load_data_from_kanbanik():
    return execute_kanbanik_command({'commandName':'getTasks','includeDescription':True,'sessionId': sessionId})['values']


def load_by_query_from_bz():
    return execute_bz_query(config['bugzilla']['loadAllQuery'])['result']['bugs']


def load_radar_from_bz(kanbanik_map):
    bzs_to_load = [k[0][0] for k in kanbanik_map if k[0][3] == 'BZ_RADAR']
    config['bugzilla']['loadSpecificBugs']['params'][0]['ids'] = bzs_to_load
    return execute_bz_query(config['bugzilla']['loadSpecificBugs'])['result']['bugs']


def execute_bz_query(query):
    try:
        bz = config['bugzilla']
        url = bz['url']
        headers = {'Content-Type': 'application/json', 'Accpet': 'application/json'}
        products = {"method": "Product.get_accessible_products"}
        raw = requests.post(url, data=json.dumps(query), headers=headers)
        return raw.json()
    except:
        logging.error("error while calling bugzilla")
        logging.error("request: " + str(query))
        logging.error("response: " + str(raw))


# expects a function returning a list of all bugzilla tasks
# returns the same list of tasks formatted as:
# ((BZ_ID, BZ_TIMESTAMP), THE_BZ)
def bz_as_map(kanbanik_map):
    # the filter part is a terrible hack, will need to find a way how to do it on the layer of bugzilla query
    by_query = [((str(bz['id']), bz['last_change_time'], bz['target_release']), bz) for bz in load_by_query_from_bz()
            if 'RFEs' not in bz['component'] and 'FutureFeature' not in bz['keywords']
            ]
    radar = [((str(bz['id']), bz['last_change_time'], bz['target_release']), bz) for bz in load_radar_from_bz(kanbanik_map)]
    return by_query + radar

# expects a function returning a list of all kanbanik tasks
# returns a list of tasks imported from bugzilla (e.g. managed by this script) in a form of:
# ((BZ_ID, BZ_TIMESTAMP, TICKET_ID), THE_WHOLE_TASK)
def kanbanik_as_map(task_loader = load_data_from_kanbanik):
    all_tasks = [(parse_metadata_from_kanbanik(task), task) for task in task_loader()]
    return filter(lambda x: x[0] != ('', '', '', ''), all_tasks)


def has_tag(task, tag):
    if task != None and task.get('taskTags') != None:
        return any([1 for t in task.get('taskTags') if t['name'].startswith(tag)])

    return False


def match_metadata(task):
    return re.match(r'.*\$BZ;(.*);TIMESTAMP;(.*)\$\$target-release(.*)\$.*', task.get('description', ''),
                     re.S | re.I)

# returns a tuple: (BZ_ID, TIMESTAMP_OF_LAST_CHANGE, TARGET_RELEASE)
def parse_metadata_from_kanbanik(task):
    matchObj = match_metadata(task)
    if matchObj:
        if has_tag(task, 'bzradar'):
            return (matchObj.group(1), matchObj.group(2), matchObj.group(3), 'BZ_RADAR')

        return (matchObj.group(1), matchObj.group(2), matchObj.group(3), 'LOADED_FROM_BZ')
    elif has_tag(task, 'bzradar'):
        bz_id = next(iter([tag['name'][4:] for tag in task.get('taskTags') if "xbz" in tag['name']]), '')
        return (bz_id, '', '', 'BZ_RADAR')
    else:
        return ('', '', '', '')


def bz_to_kanbanik(bz):
    res = {
       'commandName': 'createTask',
       'name': sanitize_string(bz[1]['summary']),
       # 'description': u'$COMMENT' + bz[1]['comments'] + '$COMMENT$BZ;' + bz[0][0] + ';TIMESTAMP;'  + bz[0][1] + '$' + '$target-release' + ','.join(bz[0][2]) + '$',
       'description': u'$COMMENT' + '$COMMENT$BZ;' + bz[0][0] + ';TIMESTAMP;'  + bz[0][1] + '$' + '$target-release' + ','.join(bz[0][2]) + '$',
       'workflowitemId': workflowitem_id_from_bz(bz[1]['status'], None),
       'version': 1,
       'projectId': user_specific_mapping(bz[1])['projectId'],
       'boardId': config['kanbanik']['boardId'],
       'sessionId': sessionId,
       'order': 0
    }

    add_assignee(res, bz[1])
    add_tags(res, bz[1])
    add_class_of_service(res, bz[1])
    add_due_date(res, bz[1])

    return res


def init_description(kanbanik, bz):
    if not match_metadata(kanbanik):
        kanbanik['description'] = u'$COMMENT' + '$COMMENT$BZ;' + bz[0] + ';TIMESTAMP;'  + bz[1] + '$' + '$target-release' + ','.join(bz[2]) + '$'


def update_bz_to_kanbanik(kanbanik, bz):
    edit = kanbanik[1].copy()

    edit['name'] = sanitize_string(bz[1]['summary'])

    init_description(edit, bz[0])
    edit['description'] = replace_timestamp(edit, bz[0][1])
    edit['description'] = replace_target_release(edit, ','.join(bz[0][2]))
    # edit['description'] = replace_comment(edit, bz[1]['comments'])
    edit['description'] = sanitize_string(edit['description'])
    edit['commandName'] = 'editTask'
    edit['sessionId'] = sessionId

    add_assignee(edit, bz[1])
    add_tags(edit, bz[1])
    add_class_of_service(edit, bz[1])
    add_due_date(edit, bz[1])
    res = [edit]

    move = edit.copy()
    result_workflowitem = workflowitem_id_from_bz(bz[1]['status'], move['workflowitemId'])

    if move['workflowitemId'] != result_workflowitem:
        move['workflowitemId'] = result_workflowitem
        move['version'] = move['version'] + 1
        move['description'] = ''
        add_assignee(move, bz[1])
        add_tags(move, bz[1])
        add_class_of_service(move, bz[1])
        add_due_date(move, bz[1])
        res.append({
            'commandName': 'moveTask',
            'task': move,
            'sessionId': sessionId
        })

    return res


def add_due_date(res, bz):
    due_date_mapping = config['bz2kanbanikMappings']['targetMilestone2dueDate']
    if 'target_milestone' in bz:
        tm = bz['target_milestone']
        if tm in due_date_mapping:
            res['dueDate'] = due_date_mapping[tm]

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
    if has_tag(kanbanik, 'xbz'):
        return

    url = re.sub(r'/jsonrpc.cgi', '/show_bug.cgi?id=' + str(bz['id']), config['bugzilla']['url'])
    bz_link = {'name': 'xbz:' + str(bz['id']), 'description': 'BZ Link', 'onClickUrl': url, 'onClickTarget': 1, 'colour': 'green'}
    tags = [bz_link]

    kanbanik['taskTags'] = tags


def user_specific_mapping(bz):
    user_mapping = config['bz2kanbanikMappings']['userSpecificMappings']
    if bz['assigned_to'] in user_mapping:
        return user_mapping[bz['assigned_to']]

    return user_mapping['unknown']


def add_assignee(kanbanik, bz):
    userName = user_specific_mapping(bz)['kanbanikName']
    kanbanik['assignee'] = {'userName': userName, 'realName': 'fake', 'pictureUrl': 'fake', 'sessionId': 'fake', 'version': 1}


def workflowitem_id_from_bz(bz_status, current_workflowitem):
    if current_workflowitem is not None and 'moveOnEditAlwaysTo' in config['bz2kanbanikMappings']:
        # unconditional move
        return config['bz2kanbanikMappings']['moveOnEditAlwaysTo']

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


def create_tasks_to_add(kanbanik_map, bz_map):
    to_enrich = [bz for bz in bz_map if bz[0][0] not in [kanbanik_task[0][0] for kanbanik_task in kanbanik_map]]
    return [bz_to_kanbanik(bz) for bz in enrich_bzs(to_enrich)]


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
    # ignore BZ comments
    return to_enrich


def bz_comment_to_kanbanik_comment(bz_comment):
    bz_comment['text'] = sanitize_string(bz_comment['text'])
    return '<br><b>' + bz_comment['author'] + '</b> Time: ' + bz_comment['creation_time'] + '<br>' + bz_comment['text'] + '<hr>'


def sanitize_string(s):
    without_non_ascii = "".join(i for i in s if ord(i)<128)
    with_correct_enters = "<br>".join(without_non_ascii.split("\n"))
    without_json_special_chars = re.sub(r'"', '\'', with_correct_enters)
    return urllib.quote_plus(without_json_special_chars)


def create_tasks_to_modify(kanbanik_map, bz_map, force_update):
    res = []
    for bz in bz_map:
        for kanbanik_task in kanbanik_map:
            if bz[0][0] == kanbanik_task[0][0] and \
                    ((bz[0][1] != kanbanik_task[0][1] or ",".join(bz[0][2]) != kanbanik_task[0][2]) or force_update):
                # finds the ones which have been changed (are both in BZ and kanbanik, but the timestamp is different)
                res.append(update_bz_to_kanbanik(kanbanik_task, bz))

    return res


def process(bz_pass, kanbanik_pass):
    initialize(bz_pass, kanbanik_pass)

    try:
        kanbanik_map = kanbanik_as_map()
        bz_map = bz_as_map(kanbanik_map)

        for task_to_add in create_tasks_to_add(kanbanik_map, bz_map):
            execute_kanbanik_command(task_to_add)

        for tasks_to_modify in create_tasks_to_modify(kanbanik_map, bz_map, False):
            for task_to_modify in tasks_to_modify:
                execute_kanbanik_command(task_to_modify)

        for unknow_task in create_tasks_to_move_to_unknown(kanbanik_map, bz_map):
            execute_kanbanik_command(unknow_task)

    finally:
        execute_kanbanik_command({'commandName': 'logout', 'sessionId': sessionId})


def synchronize(bz_pass, kanbanik_pass):
    global lock_file_path, msg
    logging.basicConfig(filename='/tmp/batuka.log', level=logging.DEBUG)
    logging.info("batuka started")
    lock_file_path = '/tmp/batuka.lock'
    if not os.path.isfile(lock_file_path):
        open(lock_file_path, 'w+')
    else:
        msg = "The lock file already exists at " + lock_file_path + ' - if you are sure no other instance of batuka is running, please deletedelete it and run batuka again.'
        logging.error(msg)
        raise Exception(msg)
    try:
        logging.info("going to process")
        process(bz_pass, kanbanik_pass)
        logging.info("process ended successfully")
    finally:
        os.remove(lock_file_path)


if __name__ == "__main__":
    kanbanik_pass = None
    bz_pass = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hk:b:", ["kanbanikpass=", "bzpass="])
    except getopt.GetoptError:
        print 'batuka.py -k <kanbanik password> -b <bugzilla password>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'batuka.py -k <kanbanik password> -b <bugzilla password>'
            sys.exit()
        elif opt in ("-k", "--kanbanikpass"):
            kanbanik_pass = arg
        elif opt in ("-b", "--bzpass"):
            bz_pass = arg

    synchronize(bz_pass, kanbanik_pass)
