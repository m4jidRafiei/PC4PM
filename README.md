## Privacy-Preserving Data Publishing in Process Mining
This project implements a web-based application for Privacy-Preserving Data Publishing (PPDP) in process mining. The application is witten in [Python](https://www.python.org/) using [Django](https://www.djangoproject.com/) framework. 
At the moment, the application has four main modules: 
* Event data management
  - In this module, you can upload and manage your event data. Both standard [XES](http://xes-standard.org/) event logs and non-standard event data, called Event Log Abstraction (ELA) resulting from some privacy preservation techniques can be handeled in this module.
* [Privacy-aware role mining](https://github.com/m4jidRafiei/privacyAware-roleMining)
  - This module implements the decomposition method proposed in the paper [Mining Roles From Event Logs While Preserving Privacy](https://www.researchgate.net/publication/334290646_Mining_Roles_From_Event_Logs_While_Preserving_Privacy). The result of applying this technique to an event log is another event log which preserves the data utility for mining roles (similar task social networks) based on the resource and activity information without revealing who performs what.
* [Connector method](https://github.com/m4jidRafiei/privacyAware-ConnectorMethod_DFG)
  - This module implements the connector method proposed in the paper [Supporting Confidentiality in Process Mining Using Abstraction and Encryption](https://www.researchgate.net/publication/338432872_Supporting_Confidentiality_in_Process_Mining_Using_Abstraction_and_Encryption) and [Ensuring Confidentiality in Process Mining](https://www.researchgate.net/publication/330042256_Ensuring_Confidentiality_in_Process_Mining). The result of applying this technique to an event log is an Event Log Abstraction (ELA) containing the directly-follows relations from the original event log which are securely stored in a data structure.
* [TLKC-privacy](https://github.com/m4jidRafiei/TLKC-Privacy)
  - This module implements the TLKC-privacy model proposed in the paper [TLKC-Privacy Model for Process Mining](https://www.researchgate.net/publication/340261780_TLKC-Privacy_Model_for_Process_Mining). This privacy model provides group-based privacy guarantees assuming four types of background knowledge: _set_, _multiset_, _sequence_, and _relative_. __T__ refers to the accuracy of timestamps in the privacy-aware event log, __L__ refers to the power of background knowledge, __K__ refers to the __k__ in the _k_-anonymity privacy model, and __C__ refers to the bound of confidence regarding the sensitive attribute values in an equivalence class. Applying this method results in a privacy-aware event log in the XES format that preserves data utility for process discovery and performance analysis.
* [TLKC-privacy-extended](https://github.com/m4jidRafiei/TLKC-Privacy-ext)
  - The extended version of TLKC-privacy provides the same type of guarantees as the main algorithm for more aspects of event data.
  The extended version of TLKC-privacy covers all the main perspectives of process mining including control-flow, time, case, and organizational perspectives. It empowers the adjustability of the proposed technique by adding new parameters to adjust privacy guarantees and the loss of accuracy. 
* [Anonymization operations](https://github.com/m4jidRafiei/PPDP-AnonOps)
  - This module implements the main anonymization operations listed in the paper [Privacy-Preserving Data Publishing in Process Mining](https://www.researchgate.net/publication/342048551_Privacy-Preserving_Data_Publishing_in_Process_Mining).
  The implemented anonymization operations are suppression, addition, condensation, swapping, generalization, cryptography, and substitution.  
* [Privacy analysis](https://github.com/m4jidRafiei/privacy_quantification)
  - This module implements the techniques for analyzing privacy of event logs proposed in [Towards Quantifying Privacy in Process Mining](https://www.researchgate.net/publication/344452810_Towards_Quantifying_Privacy_in_Process_Mining). It quantifies disclosure risks and the data utility.
  
[Privacy metadata](https://github.com/m4jidRafiei/privacy_metadata) are also embedded into the developed privacy preservation techniques.

### Features
* Each privacy preservation technique in the tool is implemented as a _Django application_ that enables the simultaneous running of different techniques on an event log. 
* New techniques can simply be integrated as independent applications. 
* The outputs for the privacy preservation techniques are provided independently for each technique and can be downloaded or stored in the event data repository.
* The tool is designed in a way that provides a cycle of privacy preservation techniques, i.e., the privacy-aware event data, added to the event data repository, can be set as the input for the techniques again as long as they are in the form of standard XES event logs. 
* To keep the process analysts aware of the modifications applied to the privacy-aware event logs, the _privacy metadata_ specify the order of the applied privacy preservation techniques. 
* A naming approach is followed to uniquely identify the privacy-aware event data based on name of the technique, the creation time, and name of the event log.    

### Requirements
The application is OS-independent, and you only need to install Django and Python packages specified in the [requirements](https://github.com/m4jidRafiei/PPDP-PM/blob/master/requirements.txt) file.

### Usage
To simplify the usage, and to run the appication without going throgh the installation phase, a [Docker container](https://hub.docker.com/r/m4jid/ppdp-pm) has been provide that can be run on your local system using the following docker commands:

```shell
docker pull m4jid/ppdp-pm-v2
docker run -d -p 8000:8000 m4jid/ppdp-pm-v2
``` 
Note that for using docker commands, first you need to [install Docker](https://docs.docker.com/get-docker/) accourding to your operation system.

After running the docker, use your browser and enter the following address to run the web-based application:
<http://127.0.0.1:8000/> 

## Other Integrations 
##### Currently, only for the first version of PPDP-PM
The introduced privacy preservation techniques have also been integrated into [PM4Py-WS (PMTK)](https://github.com/m4jidRafiei/pm4py-ws/tree/privacyIntegration) as an open-source web-based
application for process mining. Where process mining algorithms can directly be applied to the privacy-aware event logs. Use the following docker commands to run this application:

```shell
docker pull m4jid/pm4pyws:privacyIntegration
docker run -d -p 5000:80 m4jid/pm4pyws:privacyIntegration
```
After running the docker, use your browser and enter the following address to run the web-based application:
<http://127.0.0.1:5000/index.html> 

 ```shell
Credential
---------------
User: admin
Pass: admin
```

