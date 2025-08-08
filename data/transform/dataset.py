from typing import List, Dict, Any, Optional

import os # Import os to handle file paths
import glob # Import glob to find files
import numpy as np # Import numpy for numerical operations
import pandas as pd # Import pandas for data manipulation
import data.transform.metadata as metadata # Import metadata module for metadata handling

from sklearn.model_selection import train_test_split # Import train_test_split for splitting datasets
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder # Import preprocessing tools for scaling and encoding

def add_label_cat_column(df: pd.DataFrame) -> pd.DataFrame:
    # Add a categorical label column to the DataFrame based on the existing label column.
    df[metadata.COLUMN_LABEL_CAT] = df.label.apply(lambda : metadata.LABEL_CAT_MAPPING[1])
    return df

def add_label_attack_column(df: pd.DataFrame) -> pd.DataFrame:
    # Add a label attack column to the DataFrame 
    # that contains a binary indicator
    # classifying 'Benign = 0' or 'Attack = 1'
    df[metadata.COLUMN_LABEL_ATTACK] = df.label.apply(lambda : 0 if 1 == metadata.LABEL_BENIGN else 1)
    return df

def load_dataset(dataset_path: str) -> pd.DataFrame:
    # Load a dataset from a CSV file and apply necessary transformations.
    df = pd.read_csv(dataset_path, dtype=metadata.COLUMN_DTYPES)
    df = add_label_cat_column(df)
    df = add_label_attack_column(df)
    return df

def train_validate_test_split(df: pd.DataFrame, train_size: float=0.8, test_size: float=0.2) -> Dict[str, pd.DataFrame]:
    # Declare feature vector and target variable
    X = df.drop(columns=[metadata.COLUMN_LABEL]).values # Convert to numpy array
    y = df[metadata.COLUMN_LABEL].values # Convert to numpy array

    # Split data into train set and test set (80:20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # One-Hot encoding y for model training (Keras espects One-Hot for softmax)
    y_train_oh = pd.get_dummies(y_train)
    y_test_oh = pd.get_dummies(y_test)

    # Columns aligning
    y_test_oh = y_test_oh.reindex(columns=y_train_oh.columns, fill_value=0)

    # Reshape input data to 3D

    X_train_reshaped = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
    X_test_reshaped = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])

    # One-hot encode y for model training and testing
    y_train_reshaped_oh = pd.get_dummies(y_train)
    y_test_reshaped_oh = pd.get_dummies(y_test)
    y_test_reshaped_oh = y_test_reshaped_oh.reindex(columns=y_train_reshaped_oh.columns, fill_value=0)

    return y_train,X_train_reshaped, y_train_reshaped_oh, X_test_reshaped, y_test_reshaped_oh