# Configuration file to connect to the Open5gs
OPEN5GS_CONFIG = {
    'HOST': '192.168.0.115',
    'AMF_PORT': 7778, #38412
    'SMF_PORT': 7779,
    #'UPF_PORT': 7780,
    'NETWORK_INTERFACE': 'ogstun',
    'CAPTURE_FILTER': 'host{} or host{}'.format('AMF_IP', 'SMF_IP')
}