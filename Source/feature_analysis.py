import pandas as pd

# Load dataset
df = pd.read_csv("UNSW_NB15_training-set.csv")

# -----------------------------------
# Analyze categorical features
# -----------------------------------

features = ["proto", "service", "state", "attack_cat"]

for feature in features:
    print("\n" + "=" * 50)
    print(feature.upper())
    print("=" * 50)

    print(df[feature].value_counts().head(20))


# -----------------------------------
# Attack category counts
# -----------------------------------

print("\n" + "=" * 50)
print("ATTACK CATEGORY")
print("=" * 50)

print(df["attack_cat"].value_counts())