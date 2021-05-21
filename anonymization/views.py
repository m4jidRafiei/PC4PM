import shutil
import sys
from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from pp_role_mining.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper
import json
import time
import traceback

from ppdp_anonops import *
from ppdp_anonops.utils import *


from pm4py.objects.log.importer.xes import factory as xes_importer
from pm4py.objects.log.exporter.xes import factory as xes_exporter


def anonymization_main(request):
    event_log = getXesLogPath()

    appState = extractStateFromHttpRequestValues(request)
    print(appState)

    if request.method == 'POST':
        # reqValues = extractHttpRequestValues(request)
        result = {'State': 'Empty'}

        if request.is_ajax():
            # Do something here
            if(len(appState['Operations']) > 0 and appState['Action'] == "Process"):
                try:
                    return handleAnonOps(appState)
                except:
                    return HttpResponse(json.dumps({'error': str(traceback.format_exc())}), content_type='application/json', status=500)

            # Handle button calls incoming via ajax
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "addButton":
                return handleXesLogAddButtonClick(request)
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "deleteButton":
                return handleXesLogDeleteButtonClick(request)

            # Handle further ajax posts
            elif 'SaveTaxonomyTree' == getRequestParameter(request.POST, 'action', None):
                treeName = getRequestParameter(request.POST, 'treeName', None)
                treeID = getRequestParameter(request.POST, 'treeID', None)
                treeData = getRequestParameter(request.POST, 'treeData', None)
                return saveTaxonomyTree(treeID, treeName, treeData)
            elif 'DeleteTaxonomyTree' == getRequestParameter(request.POST, 'action', None):
                treeName = getRequestParameter(request.POST, 'treeName', None)
                treeID = getRequestParameter(request.POST, 'treeID', None)
                return deleteTaxonomyTree(treeID, treeName)

            # Handling of output buttons
        elif 'downloadButton' in request.POST:
            return handleXesLogDownloadButtonClick(request)

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'result': result, 'appState': json.dumps(appState)})

    else:
        if request.is_ajax():
            action = getRequestParameter(request.GET, 'action')

            if 'GetTaxonomyTreeList' == action:
                json_respone = {'taxTrees': getTaxonomyTrees("anonymization")}
                return HttpResponse(json.dumps(json_respone), content_type='application/json')
            elif 'GetTaxonomyTree' == action:
                id = getRequestParameter(request.GET, 'treeID')
                json_respone = {'taxTree': getTaxonomyTree("anonymization", id)}
                return HttpResponse(json.dumps(json_respone), content_type='application/json')

            return HttpResponse(status=204)
        else:
            return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'appState': appState})


def getXesLogPath():
    if(settings.EVENT_LOG_NAME == ':notset:'):
        return settings.EVENT_LOG_NAME

    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)
    return event_log


def extractStateFromHttpRequestValues(request):
    appState = json.loads(getRequestParameter(request.POST, 'appState', '{}'))

    if("Operations" not in appState.keys() or appState["Operations"] is None):
        appState["Operations"] = []

    if("AdditionEvents" not in appState.keys() or appState["AdditionEvents"] is None):
        appState["AdditionEvents"] = []

    if("Action" not in appState.keys() or appState["Action"] is None):
        appState["Action"] = "Nothing"

    if(("LogAttributes" not in appState.keys() or appState["LogAttributes"] is None) and getXesLogPath() != ':notset:'):
        xes_log = xes_importer.apply(getXesLogPath())

        appState["LogAttributes"] = {
            "Log": settings.EVENT_LOG_NAME,
            "CaseAttributes": getLogCaseAttributes(xes_log),
            "FirstEventUniqueAttributes": getLogFirstEventUniqueAttributes(xes_log),
            "EventAttributes": getLogEventAttributes(xes_log)
        }

    return appState


def getRequestParameter(requestData, parameter, default=None):
    if parameter in requestData:
        return requestData[parameter]
    else:
        return default


def handleAnonOps(appState):
    operations = appState["Operations"]

    start_time = time.time()
    log = xes_importer.apply(getXesLogPath())
    print("IMPORTING TOOK: --- %s seconds ---" % (time.time() - start_time))

    # Statistic data
    origNoTraces = len(log)
    origNoEvents = sum([len(trace) for trace in log])

    for op in operations:
        start_time = time.time()
        name = op["Operation"]

        if(name == 'Addition'):
            log = performAddition(log, op, appState)
        elif(name == 'Condensation'):
            log = performCondensation(log, op)
        elif(name == 'Cryptography'):
            log = performCryptography(log, op)
        elif(name == 'Generalization'):
            log = performGeneralization(log, op)
        elif(name == 'Substitution'):
            log = performSubstitution(log, op)
        elif(name == 'Suppression'):
            log = performSuppression(log, op)
        elif(name == 'Swapping'):
            log = performSwapping(log, op)

        print(name[0:3].upper() + " - " + op["Level"][0:1].upper() + " TOOK: --- %s seconds ---" % (time.time() - start_time))

    # Statistics
    print("Diff. No. of traces %0f" % (len(log) - origNoTraces))
    print("Diff. No. of events %0f" % (sum([len(trace) for trace in log]) - origNoEvents))

    newName = exportLog(log)

    return HttpResponse(json.dumps({'log': newName}), content_type='application/json')


################################
#                              #
#       Anon Op Execution      #
#                              #
################################
def performAddition(log, op, appState):
    level = op['Level']

    a = Addition()
    additionEvents = {e['Id']: e for e in appState['AdditionEvents']}

    additionOp = op['Addition-Operation']
    additionConditional = buildConditional('Addition', op, True)

    for event in additionEvents:
        eventTemplate = additionEvents[event]['Attributes']

        if(additionOp == 'Add new event as first in trace'):
            log = a.AddEventFirstInTrace(log, eventTemplate, additionConditional)
        elif(additionOp == 'Add new event as last in trace'):
            log = a.AddEventLastInTrace(log, eventTemplate, additionConditional)
        elif(additionOp == 'Add new event at random position'):
            log = a.AddEventAtRandomPlaceInTrace(log, eventTemplate, additionConditional)
    return log


def performCondensation(log, op):
    level = op['Level']

    c = Condensation()
    condenseOp = op['Condensation-Operation']
    condenseTarget = op['Condensation-Target']
    descriptiveAttributes = op['Condensation-DescriptiveAttributes']
    weights = op['Condensation-AttributeWeights']
    condenseFunc = op['Condensation-ClusterCondenseFunc']
    k = int(op['Condensation-kClusters'])

    if(level == "Event"):
        if(condenseOp == 'kMeans'):
            log = c.CondenseEventAttributeBykMeanCluster(log, condenseTarget, descriptiveAttributes, k, condenseFunc)
        elif(condenseOp == 'kModes'):
            log = c.CondenseEventAttributeBykModesCluster(log, condenseTarget, descriptiveAttributes, k, condenseFunc)
        elif(condenseOp == 'kModesEuclid'):
            log = c.CondenseEventAttributeByEuclidianDistance(log, condenseTarget, descriptiveAttributes, weights, k, condenseFunc)
    elif(level == "Case"):
        if(condenseOp == 'kMeans'):
            log = c.CondenseCaseAttributeBykMeanCluster(log, condenseTarget, descriptiveAttributes, k, condenseFunc)
        elif(condenseOp == 'kModes'):
            log = c.CondenseCaseAttributeBykModesCluster(log, condenseTarget, descriptiveAttributes, k, condenseFunc)
        elif(condenseOp == 'kModesEuclid'):
            log = c.CondenseCaseAttributeByEuclidianDistance(log, condenseTarget, descriptiveAttributes, weights, k, condenseFunc)
    return log


def performCryptography(log, op):
    level = op['Level']

    c = Cryptography()
    cryptoOp = op['Cryptography-Operation']
    cryptTarget = op['Cryptography-Target']
    conditional = buildConditional('Cryptography', op)

    if(cryptoOp == "Hash"):
        if(level == "Case"):
            log = c.HashCaseAttribute(log, cryptTarget, conditional)
        elif(level == "Event"):
            log = c.HashEventAttribute(log, cryptTarget, conditional)
    elif(cryptoOp == "Encrypt"):
        if(level == "Case"):
            log = c.EncryptCaseAttribute(log, cryptTarget, conditional)
        elif(level == "Event"):
            log = c.EncryptEventAttribute(log, cryptTarget, conditional)
    return log


def performGeneralization(log, op):
    level = op['Level']

    g = Generalization()

    tree = TaxonomyTree.CreateFromJSON(getTaxonomyTree("anonymization", op['Generalization-TaxTreeSelectionId']), "text", "children")
    generalizationTarget = op['Generalization-Target']
    generalizationDepth = op['Generalization-Depth']

    generalizationOperation = op['Generalization-Operation']
    generalizationTimeDepth = op['Generalization-TimeDepth']

    if(generalizationOperation == "GenTaxonomyTree"):
        if(level == "Case"):
            log = g.GeneralizeCaseAttributeByTaxonomyTreeDepth(log, generalizationTarget, tree, generalizationDepth)
        elif(level == "Event"):
            log = g.GeneralizeEventAttributeByTaxonomyTreeDepth(log, generalizationTarget, tree, generalizationDepth)
    elif(generalizationOperation == "GenTimestamp"):
        if(level == "Case"):
            log = g.GeneralizeCaseTimeAttribute(log, "time:timestamp", generalizationTimeDepth)
        elif(level == "Event"):
            log = g.GeneralizeEventTimeAttribute(log, "time:timestamp", generalizationTimeDepth)
    return log


def performSubstitution(log, op):
    level = op['Level']

    s = Substitution()
    subTarget = op['Substitution-Target']
    subSensitiveVal = [x.strip() for x in op['Substitution-SensitiveVal'].split(',')]
    subSubstitutionVal = [x.strip() for x in op['Substitution-SubstituteVal'].split(',')]

    if(level == "Event"):
        log = s.SubstituteEventAttributeValue(log, subTarget, subSensitiveVal, subSubstitutionVal)
    elif(level == "Case"):
        log = s.SubstituteCaseAttributeValue(log, subTarget, subSensitiveVal, subSubstitutionVal)
    return log


def performSuppression(log, op):
    level = op['Level']

    s = Suppression()
    suppressionOP = op['Suppression-Operation']
    suppressionTarget = op['Suppression-Target']
    conditional = buildConditional('Suppression', op)

    if(level == "Event"):
        if(suppressionOP == "Suppress"):
            log = s.SuppressEvent(log, conditional)
        elif(suppressionOP == "SuppressAttribute"):
            log = s.SuppressEventAttribute(log, suppressionTarget, conditional)
    elif(level == "Case"):
        if(suppressionOP == "Suppress"):
            log = s.SuppressCase(log, conditional)
        elif(suppressionOP == "SuppressAttribute"):
            log = s.SuppressCaseAttribute(log, suppressionTarget, conditional)
    return log


def performSwapping(log, op):
    level = op['Level']

    s = Swapping()
    swapOp = op['Swapping-Operation']
    swapTarget = op['Swapping-Target']
    descriptiveAttributes = op['Swapping-DescriptiveAttributes']
    weights = op['Swapping-AttributeWeights']
    k = int(op['Swapping-kClusters'])

    if(level == "Event"):
        if(swapOp == 'kMeans'):
            log = s.SwapEventAttributeValuesBykMeanCluster(log, swapTarget, descriptiveAttributes, k)
        elif(swapOp == 'kModes'):
            log = s.SwapEventAttributeBykModesClusterUsingMode(log, swapTarget, descriptiveAttributes, k)
        elif(swapOp == 'kModesEuclid'):
            log = s.SwapEventAttributeByEuclidianDistance(log, swapTarget, descriptiveAttributes, weights, k)
    elif(level == "Case"):
        if(swapOp == 'kMeans'):
            log = s.SwapCaseAttributeValuesBykMeanCluster(log, swapTarget, descriptiveAttributes, k)
        elif(swapOp == 'kModes'):
            log = s.SwapCaseAttributeBykModesClusterUsingMode(log, swapTarget, descriptiveAttributes, k)
        elif(swapOp == 'kModesEuclid'):
            log = s.SwapCaseAttributeByEuclidianDistance(log, swapTarget, descriptiveAttributes, weights, k)
    return log
# Building both conditional filters (case and event) for thegiven operation


def buildConditional(operation, cfg, onlyCase=False):
    isConditionalActive = cfg[operation + '-ConditionalActive-Case']
    condAttCase = cfg[operation + '-ConditionalAttr-Case'] if isConditionalActive else None
    condValCase = cfg[operation + '-ConditionalVal-Case'] if isConditionalActive else None
    condModCase = cfg[operation + '-MatchOp-Case'] if isConditionalActive else None
    condOprCase = cfg[operation + '-ConditionalOperator-Case'] if isConditionalActive else None
    condCase = getConditionalLambda(condModCase, condAttCase, condValCase, condOprCase)

    if(not onlyCase):
        isConditionalActive = cfg[operation + '-ConditionalActive-Event']
        condAttEvent = cfg[operation + '-ConditionalAttr-Event'] if isConditionalActive else None
        condValEvent = cfg[operation + '-ConditionalVal-Event'] if isConditionalActive else None
        condModEvent = cfg[operation + '-MatchOp-Event'] if isConditionalActive else None
        condOprEvent = cfg[operation + '-ConditionalOperator-Event'] if isConditionalActive else None
        condEvent = getConditionalLambda(condModEvent, condAttEvent, condValEvent, condOprEvent)
        return (lambda c, e: condCase(c, e) and condEvent(c, e))

    return (lambda c, e: condCase(c, e))

# Constructing the lambdas for the conditional filters and generating operator lambdas


def getConditionalLambda(matchOperation, attribute, value, operator):
    op = (lambda l, r: True)

    if(operator == "=="):
        op = (lambda l, r: str(l) == str(r))
    elif(operator == ">="):
        op = (lambda l, r: float(l) >= float(r))
    elif(operator == "<="):
        op = (lambda l, r: float(l) <= float(r))
    elif(operator == ">"):
        op = (lambda l, r: float(l) > float(r))
    elif(operator == "<"):
        op = (lambda l, r: float(l) < float(r))
    elif(operator == "!="):
        op = (lambda l, r: str(l) != str(r))
    elif(operator == "in"):
        op = (lambda l, r: l in [x.strip() for x in r.split(',')])
    elif(operator == "not in"):
        op = (lambda l, r: l not in [x.strip() for x in r.split(',')])

    if(matchOperation == "matchCase"):
        return (lambda c, e: attribute in c.attributes.keys() and op(c.attributes[attribute], value))
    elif(matchOperation == "matchTraceLength"):
        return (lambda c, e: op(len(c), value))
    elif(matchOperation == "matchFirstEvent"):
        return (lambda c, e: len(c) > 0 and attribute in c[0].keys() and op(c[0][attribute], value))
    elif(matchOperation == "matchLastEvent"):
        return (lambda c, e: len(c) > 0 and attribute in c[-1].keys() and op(c[-1][attribute], value))
    elif(matchOperation == "matchAnyEvent"):
        return (lambda c, e: len(c) > 0 and len([x for x in c if attribute in x.keys() and op(x[attribute], value)]) > 0)
    elif(matchOperation == "matchAllEvent"):
        return (lambda c, e: len(c) > 0 and len([x for x in c if attribute in x.keys() and op(x[attribute], value)]) == len(c))
    elif(matchOperation == "eventAttribute"):
        return (lambda c, e: attribute in e.keys() and op(e[attribute], value))
    else:
        return (lambda c, e: True)

################################
#                              #
#       HELPER FUNCTIONS       #
#                              #
################################


def getLogCaseAttributes(xesLog):
    case_attribs = []
    for case_index, case in enumerate(xesLog):
        for key in case.attributes.keys():
            if key not in case_attribs and not key.startswith("@"):
                case_attribs.append(key)
    return sorted(case_attribs)
    pass


def getLogFirstEventUniqueAttributes(xesLog):
    uniqueAttr = []
    for cIndex, case in enumerate(xesLog):
        for eIndex, event in enumerate(case):
            if(eIndex == 0 and cIndex == 0):
                uniqueAttr = list(event.keys())
            elif(eIndex > 0):
                for key in event.keys():
                    if(key in uniqueAttr):
                        uniqueAttr.remove(key)

    return sorted(uniqueAttr)
    pass


def getLogEventAttributes(xesLog):
    event_attribs = []
    for case_index, case in enumerate(xesLog):
        for event_index, event in enumerate(case):
            for key in event.keys():
                if key not in event_attribs and not key.startswith("@"):
                    event_attribs.append(key)
    return sorted(event_attribs)
    pass


def getOutputFileList(directory):
    return getFileList(os.path.join(settings.MEDIA_ROOT, "temp"), directory)


def getTaxonomyTrees(directory):
    return getFileList(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory)


def getTaxonomyTree(directory, id):
    files = getFileList(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory)
    for name in files:
        if name.startswith(id):
            filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory, name)
            f = open(filePath, "r")
            data = f.read()
            f.close()
            return data
    return None


def getFileList(path, directory):
    output_path = os.path.join(path, directory)

    if(not os.path.exists(output_path)):
        os.mkdir(output_path)

    return [f for f in os.listdir(output_path) if os.path.isfile(os.path.join(output_path, f))]


def saveTaxonomyTree(treeID, treeName, treeData):
    filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), "anonymization", treeID + " - " + treeName + ".json")

    os.makedirs(os.path.dirname(filePath), exist_ok=True)

    f = open(filePath, "w")
    f.write(treeData)
    f.close()
    return HttpResponse(status=204)


def deleteTaxonomyTree(treeID, treeName):
    filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), "anonymization", treeID + " - " + treeName + ".json")
    os.remove(filePath)
    return HttpResponse(status=204)


def handleXesLogDownloadButtonClick(request):
    if "output_list" not in request.POST:
        return HttpResponseRedirect(request.path_info)

    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    filename = request.POST["output_list"]
    file_dir = os.path.join(temp_path, "anonymization", filename)

    try:
        wrapper = FileWrapper(open(file_dir, 'rb'))
        response = HttpResponse(wrapper, content_type='application/force-download')
        response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
        return response
    except Exception as e:
        return None


def handleXesLogAddButtonClick(request):
    filename = getRequestParameter(request.POST, 'selectedFile', None)
    if filename is not None:
        temp_path = os.path.join(settings.MEDIA_ROOT, "temp", "anonymization", filename)
        event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs", filename)
        shutil.move(temp_path, event_logs_path)

        if temp_path == settings.ROLE_FILE:
            settings.ROLE_FILE = ""
            settings.ROLE_APPLIED = False

    return HttpResponse(status=204)


def handleXesLogDeleteButtonClick(request):
    filename = getRequestParameter(request.POST, 'selectedFile', None)
    if filename is not None:
        temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

        file_dir = os.path.join(temp_path, "anonymization", filename)
        os.remove(file_dir)

        if file_dir == settings.ROLE_FILE:
            settings.ROLE_FILE = ""
            settings.ROLE_APPLIED = False

    return HttpResponse(status=204)


def exportLog(log):
    now = datetime.now()
    dateTime = now.strftime(" %m-%d-%y %H-%M-%S ")
    newName = "anon" + dateTime + settings.EVENT_LOG_NAME[:-3] + "xes"
    tmpPath = os.path.join(settings.MEDIA_ROOT, "temp")
    newFile = os.path.join(tmpPath, "anonymization", newName)

    start_time = time.time()
    xes_exporter.export_log(log, newFile)
    print("EXPORTING TOOK: --- %s seconds ---" % (time.time() - start_time))
    return newName
