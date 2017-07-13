
# OpenDXL-WildFireTIE
The Wildfire TIE DXL Python application polls the Wildfire analysis data and updates TIE over the DXL fabric.

## Introduction

Customers are regularly challenged by having made multiple high dollar investments in disjointed best of breed solutions. As such, point-to-point integration is usually required to bridge the gap in architectures offering synergistic value to the organization. And, since WildFire is a very popular sandbox technology from PaloAlto Networks that many customers employ, this module integrates the value of WildFire sandboxing technologies, cloud or on premise appliances, with the effective threat mitigation at the endpoint offered by McAfee's Threat Intelligence Exchange (TIE).

## Startup
  Launch the integration process by executing:
  
  ```
  #python wf.py
  ```

## Setup

To run OpenDXL-WildFireTIE install Python 2.7 or later. Python 3 is not currently supported. 

Install the required dependencies with the requirements.txt file:

```sh
$ pip install -r requirements.txt
```

This will install the requests module.

### McAfee OpenDXL SDK

https://www.mcafee.com/us/developers/open-dxl/index.aspx

McAfee Threat Intelligence Exchange (TIE) DXL Python Client Library at the follow link:

https://github.com/opendxl/opendxl-tie-client-python/wiki

* Certificate Files Creation [link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html)
* ePO Certificate Authority (CA) Import [link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html)
* ePO Broker Certificates Export  [link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html)



### Edit the dxlclient.config

Provision DXL client certificates and fill in the broker list for the DXL Client.

```
[Certs]
BrokerCertChain=certs/brokercert.crt
CertFile=certs/client.crt
PrivateKey=certs/client.key

[Brokers]
{}={};8883;
```

For more information on configuring the DXL client see the [OpenDXL Python Client SDK Documentation](https://opendxl.github.io/opendxl-client-python/pydoc/index.html)

### wf.config

Update the wf.config file with the WildFire API key. Please consult the WildFire documentation for steps to obtain the key.
It is recommended to use the WildFire appliance as your source for intelligence.

wf_age: How far back should the WildFire repository go?

wf_host: This defaults to WildFire cloud. Please update with the location of your appliance if you have a WildFire on-premise deployment.

```
[wildfire]
apikey=<API KEY FROM WILDFIRE>
wf_age=1

# This is the default cloud instance which returns all entries
# not just what your organization submitted. Please change this to your
# appliance if you have one
wf_host=https://wildfire.paloaltonetworks.com
```
