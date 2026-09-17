import pandas as pd

# Load datasets
train = pd.read_csv("UNSW_NB15_training-set.csv")
test = pd.read_csv("UNSW_NB15_testing-set.csv")

# -------------------------------
# 1. Basic information
# -------------------------------

print("Training shape:", train.shape)
print("Testing shape:", test.shape)

# -------------------------------
# 2. Dataset information
# -------------------------------

print("\nTraining dataset information:")
print(train.info())

# -------------------------------
# 3. Missing values
# -------------------------------

print("\nMissing values:")
print(train.isnull().sum())

# -------------------------------
# 4. Attack category distribution
# -------------------------------

print("\nAttack category distribution:")
print(train["attack_cat"].value_counts())

# -------------------------------
# 5. Attack category percentage
# -------------------------------

print("\nAttack category percentage:")
print(train["attack_cat"].value_counts(normalize=True) * 100)

# -------------------------------
# 6. Normal vs Attack
# -------------------------------

print("\nNormal vs Attack:")
print(train["label"].value_counts())

# -------------------------------
# 7. Numerical summary
# -------------------------------

print("\nNumerical feature summary:")
print(train.describe())