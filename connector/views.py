import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from p_connector_dfg.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper


def connector_main(request):
    if request.method == 'POST':

        if 'applyButton' in request.POST:

            event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

            if settings.EVENT_LOG_NAME == ':notset:':
                return HttpResponseRedirect(request.path_info)

            relationDepth = False
            traceLength = False
            traceId = False

            values = setValues(request)
            outputs = get_output_list("connector")

            if len(values['enkey']) != 16:
                msg_text = 'The encryption key size should be 128 (16 characters)!'
                return render(request, 'connector_main.html',
                              {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs, 'message':msg_text})


            pma_method = "Connector Method"
            pma_desired_analyses = ['directly follows graph', 'process discovery']

            now = datetime.now()
            date_time = now.strftime(" %m-%d-%y %H-%M-%S ")
            new_file_name = "connector" + date_time + settings.EVENT_LOG_NAME[:-3] +"xml"
            pma_path = os.path.join(temp_path, "connector", new_file_name)

            settings.CONNECTOR_FILE = pma_path
            settings.CONNECTOR_APPLIED = True

            if 'relationDepth' in values:
                relationDepth = True
            if 'traceLength' in values:
                traceLength = True
            if 'traceId' in values:
                traceId = True


            event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)

            pp = privacyPreserving(event_log)
            pp.apply_privacyPreserving(values['enkey'],pma_path, pma_method, pma_desired_analyses, event_log, relation_depth = relationDepth, trace_length = traceLength, trace_id = traceId)

            if os.path.isfile(settings.CONNECTOR_FILE):
                values['load'] = False
            else:
                values['load'] = True

            outputs.append(new_file_name)

            return render(request,'connector_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':values, 'outputs':outputs})

        elif 'downloadButton' in request.POST:

            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
            filename = request.POST["output_list"]
            file_dir = os.path.join(temp_path, "connector", filename)

            try:
                wrapper = FileWrapper(open(file_dir, 'rb'))
                response = HttpResponse(wrapper, content_type='application/force-download')
                response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
                return response
            except Exception as e:
                return None


        elif "deleteButton" in request.POST:
            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            filename = request.POST["output_list"]
            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

            file_dir = os.path.join(temp_path, "connector", filename)
            os.remove(file_dir)

            if file_dir == settings.CONNECTOR_FILE:
                settings.CONNECTOR_FILE =""
                settings.CONNECTOR_APPLIED = False

            outputs = get_output_list("connector")
            values = setValues(request)

            return render(request, 'connector_main.html',
                          {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})

        elif 'addButton' in request.POST:

            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            filename = request.POST["output_list"]

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp", "connector", filename)
            n_event_logs_path = os.path.join(settings.MEDIA_ROOT, "none_event_logs", filename)
            shutil.move(temp_path, n_event_logs_path)

            if temp_path == settings.CONNECTOR_FILE:
                settings.CONNECTOR_FILE = ""
                settings.CONNECTOR_APPLIED = False

            outputs = get_output_list("connector")

            values = setValues(request)
            return render(request, 'connector_main.html',
                          {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})

    else:
        values = {}
        values['relationDepth'] = 'relationDepth'
        values['traceLength'] = 'traceLength'
        values['traceId'] = 'traceId'
        values['enkey'] = 'DEFPASSWORD12!!!'

        if not (os.path.isfile(settings.CONNECTOR_FILE)) and settings.CONNECTOR_APPLIED:
            values['load'] = True
        else:
            settings.CONNECTOR_APPLIED = False
            values['load'] = False

        outputs = get_output_list("connector")

        return render(request, 'connector_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':values, 'outputs':outputs})


def setValues(request):
    values = {}
    if 'relationDepth' in request.POST:
        values['relationDepth'] = request.POST['relationDepth']
    if 'traceLength' in request.POST:
        values['traceLength'] = request.POST['traceLength']
    if 'traceId' in request.POST:
        values['traceId'] = request.POST['traceId']
    if 'enkey' in request.POST:
        values['enkey'] = request.POST['enkey']

    return values


def get_output_list(directory):
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    output_path = os.path.join(temp_path, directory)
    outputs = [f for f in os.listdir(output_path) if
                           os.path.isfile(os.path.join(output_path, f))]
    return outputs
