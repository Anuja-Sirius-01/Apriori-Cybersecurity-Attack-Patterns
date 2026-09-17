import pandas as pd

# Load training dataset
df = pd.read_csv("UNSW_NB15_training-set.csv")

print("Original shape:", df.shape)

# -----------------------------------
# Select categorical features
# -----------------------------------

categorical_features = [
    "proto",
    "service",
    "state",
    "attack_cat"
]

# Keep only selected columns
apriori_data = df[categorical_features].copy()

print("\nSelected features:")
print(apriori_data.head())

# -----------------------------------
# Check unique values
# -----------------------------------

for column in categorical_features:
    print(f"\n{column} unique values:")
    print(apriori_data[column].nunique())

# -----------------------------------
# Check missing values
# -----------------------------------

print("\nMissing values:")
print(apriori_data.isnull().sum())

# -----------------------------------
# Display final data
# -----------------------------------

print("\nData prepared for Apriori:")
print(apriori_data.head(10))