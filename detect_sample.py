# Import necessary libraries
import numpy as np
import flask
import pickle
from flask import Flask, request

# Import Deep Learning model
dl_model = pickle.load(open("models/vanilla_lstm_model.pkl", "rb"))

# Initialize Flask app
app = Flask(__name__)