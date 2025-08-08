from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer # Import ColumnTransformer for applying transformations to specific columns
from sklearn.pipeline import Pipeline # Import Pipeline for creating a sequence of transformations

# Import original dataset 1 and 2 combined
df = pd.read_csv('/data/original/NIDD_5G_Train_Full-1.csv') + pd.read_csv('/data/original/NIDD_5G_Train_Full-2.csv')

# Drop unnecessary qualitative columns
columns_to_drop = ['ip.src', 'ip.dst', 'eth.src', 'eth.dst', 'flow.id']
df.drop(columns=columns_to_drop, inplace=True)

# Remove attribute column 'label' from categorical for later encoding
target_col = 'label'
qualitative_attributes = df.select_dtypes(include=['object'])
categorical_features = df.drop([col for col in qualitative_attributes.columns if col != target_col], axis=1)

# Fill in numerical features' nulls with median
quantitative_attributes = df.select_dtypes(include=['int64', 'float64'])
for col in quantitative_attributes.columns:
  df[col] = df[col].fillna(df[col].median())

# Remove duplicate rows
df.drop_duplicates(inplace=True)

