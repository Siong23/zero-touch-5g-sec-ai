import joblib
import numpy as np
import logging
import json

from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages

from .forms import CapturedDataForm

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load trained model
model = joblib.load(r'C:\Users\user\zero-touch-5g-sec-ai\models\vanilla_lstm_model.pkl')

def home(request):
    detection = None
    accuracy = None

    if request.method == 'POST':
        form = CapturedDataForm(request.POST)
        if form.is_valid():
            captured_data = form.cleaned_data['captured_data']

            if model is None:
                messages.error(request, "Model is not loaded.")
                return render(request, 'index.html', {'form': form, 'detection': "Error: Model not loaded!", 'accuracy': "N/A"})
            
            # Parse the data
            if captured_data.strip().startswith('['):
                data_list = json.loads(captured_data)
            else:
                data_list = [float(x) for x in captured_data.split(',')]

            # Reshape the data into 3D array to fit in LSTM input format
            data_array = np.array(data_list).flatten().reshape(1, -1, 14)


            detection = model.predict(data_array)

            attack_types = {
                0: "Benign",
                1: "HTTPFlood",
                2: "ICMPFlood",
                3: "SYNFlood",
                4: "SYNScan",
                5: "SlowrateDoS",
                6: "TCPConnectScan",
                7: "UDPFlood",
                8: "UDPScan"
            }

            accuracy = np.random.rand()  # Replace with actual accuracy from your model
    
    else:
        form = CapturedDataForm()
    return render(request, 'index.html', {'form': form, 'detection': detection, 'accuracy': accuracy})