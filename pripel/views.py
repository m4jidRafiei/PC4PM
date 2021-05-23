import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper
from pm4py.objects.log.importer.xes import factory as xes_importer_factory

from pp_pripel.pripel import PRIPEL


def pripel_main(request):
    if not os.path.exists(os.path.join(os.path.join(settings.MEDIA_ROOT, "temp"), "pripel")):
        os.makedirs(os.path.join(os.path.join(settings.MEDIA_ROOT, "temp"), "pripel"))

    if request.method == 'POST':
        event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
        event_log_name = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)

        if 'applyButton' in request.POST:

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

            if settings.EVENT_LOG_NAME == ':notset:':
                return HttpResponseRedirect(request.path_info)

            values = setValues(request)

            privacy_aware_log_dir = os.path.join(temp_path, "pripel")

            epsilon = float(values['epsilon'])
            n = int(values['n'])
            k = int(values['k'])

            log_name = settings.EVENT_LOG_NAME[:-4]
            #Only for consistency!
            now = datetime.now()
            date_time = now.strftime(" %m-%d-%y %H-%M-%S ")
            fixed_name = "pripel" + date_time + log_name + " "

            privacy_aware_log_path = os.path.join(fixed_name + str(epsilon) + "_" + str(n) + "_" + str(k) + ".xes")



            settings.PRIPEL_FILE = os.path.join(privacy_aware_log_dir,privacy_aware_log_path)
            settings.PRIPEL_APPLIED = True

            pripel = PRIPEL()
            result_file = pripel.apply(event_log_name,epsilon,n,k)
            exportLog(result_file, settings.PRIPEL_FILE)




            print(settings.PRIPEL_FILE)
            if os.path.isfile(settings.PRIPEL_FILE):
                values['load'] = False
            else:
                values['load'] = True

            outputs = get_output_list("pripel")

            return render(request, 'pripel_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})

        elif 'downloadButton' in request.POST:
            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
            filename = request.POST["output_list"]
            file_dir = os.path.join(temp_path,"pripel", filename)

            try:
                wrapper = FileWrapper(open(file_dir, 'rb'))
                response = HttpResponse(wrapper, content_type='application/force-download')
                response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
                return response
            except Exception as e:
                return None

        elif 'addButton' in request.POST:

            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            filename = request.POST["output_list"]

            temp_name = os.path.join(settings.MEDIA_ROOT, "temp", "pripel", filename)
            event_name = os.path.join(settings.MEDIA_ROOT, "event_logs", filename)
            shutil.move(temp_name, event_name)

            if temp_name == settings.PRIPEL_FILE:
                settings.PRIPEL_FILE = ""
                settings.PRIPEL_APPLIED = False

            outputs = get_output_list("pripel")

            values = setValues(request)

            xes_log = xes_importer_factory.apply(event_log_name)

            return render(request, 'pripel_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})

        elif "deleteButton" in request.POST:

            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            filename = request.POST["output_list"]
            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
            file_dir = os.path.join(temp_path, "pripel", filename)

            os.remove(file_dir)

            if file_dir == settings.pripel_FILE:
                settings.PRIPEL_FILE =""
                settings.PRIPEL_APPLIED = False

            outputs = get_output_list("pripel")
            values = setValues(request)

            return render(request, 'pripel_main.html',
                          {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})


    else:

        values = {}
        values = {}
        values['epsilon'] = 0.1
        values['n'] = 5
        values['k'] = 10

        outputs = get_output_list("pripel")

        if not (os.path.isfile(settings.PRIPEL_FILE)) and settings.PRIPEL_APPLIED:
            values['load'] = True
        else:
            settings.pripel_APPLIED = False
            values['load'] = False

        if settings.EVENT_LOG_NAME != ':notset:':
            event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
            file_dir = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)
            xes_log = xes_importer_factory.apply(file_dir)

        return render(request, 'pripel_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':values, 'outputs':outputs})


def setValues(request):
    values = {}
    values['epsilon'] = request.POST['epsilon']
    values['n'] = request.POST['n']
    values['k'] = request.POST['k']

    return values


def get_output_list(directoty):
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    output_path = os.path.join(temp_path, directoty)
    outputs = [f for f in os.listdir(output_path) if
                           os.path.isfile(os.path.join(output_path, f))]
    return outputs

def get_attributes(xes_log):
    sensitives = []
    case_attribs = []
    for case_index, case in enumerate(xes_log):
        for key in case.attributes.keys():
            if key not in case_attribs:
                case_attribs.append(key)

    event_attribs = []
    for case_index, case in enumerate(xes_log):
        for event_index, event in enumerate(case):
            for key in event.keys():
                if key not in event_attribs:
                    event_attribs.append(key)

    sensitives = case_attribs + event_attribs
    sensitives.sort()
    return sensitives

def exportLog(log, fullPath):
    start_time = time.time()
    xes_exporter.export_log(log, fullPath)
    print("EXPORTING TOOK: --- %s seconds ---" % (time.time() - start_time))
    return newName
