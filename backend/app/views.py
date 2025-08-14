import joblib
import numpy as np

from django.shortcuts import render
from django.core.files.storage import default_storage

from .forms import CapturedDataForm

# Load trained model
model = joblib.load(r'C:\Users\user\zero-touch-5g-sec-ai\models\vanilla_lstm_model.pkl')

def home(request):
    detection = None
    accuracy = None
    if request.method == 'POST':
        form = CapturedDataForm(request.POST)
        if form.is_valid():
            captured_data = form.cleaned_data['captured_data']
            data_array = np.array(captured_data).flatten().reshape(1, -1, 14)
            detection = model.predict(data_array)[0]
            accuracy = np.random.rand()  # Replace with actual accuracy from your model
    
    else:
        form = CapturedDataForm()
    return render(request, 'index.html', {'form': form, 'detection': detection, 'accuracy': accuracy})