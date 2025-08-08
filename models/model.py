import sys
from typing import List, Dict, Any, Optional
from sklearn.pipeline import pipeline
import logging
import pandas as pd
from sklearn.preprocessing import FunctionTransformer

from tensorflow import keras
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Layer, Input, LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils  import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.model_selection import KFold

from data.transform.dataset import train_validate_test_split

# Set up logger
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
log = logging.getLogger(__name__)

def build_model(y_train, X_train_reshaped, y_train_reshaped_oh, X_test_reshaped, y_test_reshaped_oh):

    # Add callbacks for better training control
    callbacks = [
        EarlyStopping(
            monitor='val_loss',
            mode='min',
            patience=5,
            verbose=1,
            restore_best_weights=True
        ),
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.1,
            patience=3,
            verbose=1
        )
    ]

    # Define the Vanilla LSTM model
    from sklearn.preprocessing import label_binarize

    kf = KFold(n_splits=5, shuffle=True, random_state=42) # Reduced number of splits
    preds = []
    fold = 0

    # Binarize the true labels for one-vs-rest ROC
    y_train_bin = label_binarize(y_train, classes=np.unique(y_train))

    for train_idx, val_idx in kf.split(X_train_reshaped):
        X_train_fold = X_train_reshaped[train_idx]
        y_train_fold_oh = y_train_reshaped_oh.values[train_idx]
        X_val_fold = X_train_reshaped[val_idx]
        y_val_fold_oh = y_train_reshaped_oh.values[val_idx]

        inputs = Input(shape=(X_train_reshaped.shape[1], X_train_reshaped.shape[2]))
        x = LSTM(64, return_sequences=False)(inputs)
        x = Dropout(0.3)(x)
        outputs = Dense(y_train_reshaped_oh.shape[1], activation='softmax')(x)
        vanilla_lstm_model = Model(inputs, outputs, name="Vanilla_LSTM")
        model = vanilla_lstm_model
        model.fit(X_train_fold, y_train_fold_oh, epochs=3, batch_size=128, verbose=1, validation_data=(X_val_fold, y_val_fold_oh))

        preds_val = model.predict(X_val_fold)
        preds.append(preds_val)
        fold += 1



