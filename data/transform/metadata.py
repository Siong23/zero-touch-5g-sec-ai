COLUMN_DTYPES = {
    "frame.time_relative": "float64",
    "ip.src": "object",
    "ip.dst": "object",
    "ip.len": "int64",
    "tcp.flags.syn": "float64",
    "tcp.flags.ack": "float64",
    "tcp.flags.push": "float64",
    "tcp.flags.fin": "float64",
    "tcp.flags.reset": "float64",
    "tcp.flags.ece": "float64",
    "ip.proto": "int64",
    "eth.src": "object",
    "eth.dst": "object",
    "ip.hdr_len": "int64",
    "ip.ttl": "int64",
    "tcp.window_size_value": "int64",
    "tcp.hdr_len": "int64",
    "udp.length": "int64",
    "srcport": "int64",
    "dstport": "int64",
    "flow.id": "object",
    "label": "object"
}

LABEL_BENIGN = "Benign"

LABEL_CAT_MAPPING = {
    "Benign": "0",
    "HTTPFlood": "1",
    "ICMPFlood": "2",
    "SYNFlood": "3",
    "SYNScan": "4",
    "SlowrateDoS": "5",
    "TCPConnectScan": "6",
    "UDPFlood": "7",
    "UDPScan": "8"
}

FEATURES_TO_DROP = [
    "ip.src",
    "ip.dst",
    "eth.src",
    "eth.dst",
    "flow.id",
    "tcp.flags.ece",
    "ip.hdr_len"
]

COLUMN_LABEL = "label"
COLUMN_LABEL_CAT = "label_cat"
COLUMN_LABEL_ATTACK = "label_attack"