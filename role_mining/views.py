import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from pp_role_mining.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper


def role_main(request):
    if request.method == 'POST':

        if 'applyButton' in request.POST:

            event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

            if settings.EVENT_LOG_NAME == ':notset:':
                return HttpResponseRedirect(request.path_info)

            values = setValues(request)

            MinMax = [True, True]
            if values['LowerUpper'] == "LowerUpper":
                MinMax = [True, True]
            elif values['LowerUpper'] == "Lower":
                MinMax = [True, False]
            elif values['LowerUpper'] == "Upper":
                MinMax = [False, True]

            resource_aware = False
            hashedActivities = False

            if 'resourceAware' in values:
                resource_aware = True
            if 'hashedAct' in values:
                hashedActivities =True

            show_final_result = False

            event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)
            exportPrivacyAwareLog = True

            now =datetime.now()
            date_time = now.strftime(" %m-%d-%y %H-%M-%S ")
            new_file_name = values['RoleMining_Tech'] + date_time + settings.EVENT_LOG_NAME
            privacy_aware_log_path = os.path.join(temp_path, "role_mining", new_file_name)

            settings.ROLE_FILE = privacy_aware_log_path
            settings.ROLE_APPLIED = True

            pp = privacyPreserving(event_log)
            pp.apply_privacyPreserving(values['RoleMining_Tech'], resource_aware, exportPrivacyAwareLog, show_final_result,
                                       hashedActivities, NoSubstitutions= int(values['fixedValue']), MinMax=MinMax,
                                       FixedValue=int(values['fixedValueFreq']), privacy_aware_log_path=privacy_aware_log_path,
                                       # event_attribute2remove=["Activity", "Resource", "Costs"],
                                       # case_attribute2remove=["creator"]
                                        )
            if os.path.isfile(settings.ROLE_FILE):
                values['load'] = False
            else:
                values['load'] = True

            outputs = get_output_list("role_mining")

            return render(request,'role_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':values, 'outputs':outputs})

        elif 'downloadButton' in request.POST:
            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
            filename = request.POST["output_list"]
            file_dir = os.path.join(temp_path,"role_mining", filename)

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

            temp_path = os.path.join(settings.MEDIA_ROOT, "temp", "role_mining", filename)
            event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs", filename)
            shutil.move(temp_path, event_logs_path)

            if temp_path == settings.ROLE_FILE:
                settings.ROLE_FILE =""
                settings.ROLE_APPLIED = False

            outputs = get_output_list("role_mining")

            values = setValues(request)
            return render(request, 'role_main.html',
                          {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})

        elif "deleteButton" in request.POST:

            if "output_list" not in request.POST:
                return HttpResponseRedirect(request.path_info)

            filename = request.POST["output_list"]
            temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

            file_dir = os.path.join(temp_path, "role_mining", filename)
            os.remove(file_dir)

            if file_dir == settings.ROLE_FILE:
                settings.ROLE_FILE =""
                settings.ROLE_APPLIED = False

            outputs = get_output_list("role_mining")
            values = setValues(request)

            return render(request, 'role_main.html',
                          {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})


    else:
        values = {}
        values['fixedValue'] = 2
        values['LowerUpper'] = 'LowerUpper'
        values['fixedValueFreq'] = 1
        values['resourceAware'] = 'resourceAware'
        values['hashedAct'] = 'hashedAct'

        if not (os.path.isfile(settings.ROLE_FILE)) and settings.ROLE_APPLIED:
            values['load'] = True
        else:
            settings.ROLE_APPLIED = False
            values['load'] = False


        outputs = get_output_list("role_mining")

        return render(request, 'role_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':values, 'outputs':outputs})


def setValues(request):
    values = {}
    values['RoleMining_Tech'] = request.POST['RoleMining_Tech']
    values['fixedValue'] = request.POST['fixedValue']
    values['LowerUpper'] = request.POST['LowerUpper']
    values['fixedValueFreq'] = request.POST['fixedValueFreq']
    if 'resourceAware' in request.POST:
        values['resourceAware'] = request.POST['resourceAware']
    if 'hashedAct' in request.POST:
        values['hashedAct'] = request.POST['hashedAct']

    return values


def get_output_list(directoty):
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    output_path = os.path.join(temp_path, directoty)
    outputs = [f for f in os.listdir(output_path) if
                           os.path.isfile(os.path.join(output_path, f))]
    return outputs
