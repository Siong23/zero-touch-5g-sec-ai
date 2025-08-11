from django.test import TestCase
from .ids.vanilla_lstm import VanillaLSTM

class VanillaLSTMTests(TestCase):
    def test_lstm_algorithm(self):
        data = {
            "frame.time_relative": -1.909990713,
            "ip.len": -0.720828222,
            "tcp.flags.syn": -0.210455971,
            "tcp.flags.ack": 0.17171146,
            "tcp.flags.push": -0.363892373,
            "tcp.flags.fin": -0.119927617,
            "tcp.flags.reset": -0.125807304,
            "ip.proto": -2.182787826,
            "ip.ttl": -0.696464265,
            "tcp.window_size_value": -0.212153377,
            "tcp.hdr_len": -0.765434182,
            "udp.length": -0.639727849,
            "srcport": -0.843824564,
            "dstport": -0.972929059,
            "label": 0
        }

        model = VanillaLSTM()
        self.assertIsNotNone(model)
        response = model.compute_prediction(data)
        self.assertEqual('OK', response['status'])
        self.assertTrue('label' in response)