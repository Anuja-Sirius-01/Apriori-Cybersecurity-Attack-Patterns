import pandas as pd

# Load validated rules
df = pd.read_csv("attack_pattern_validation.csv")

# Calculate confidence change
df["confidence_change"] = (
    df["test_confidence"] - df["training_confidence"]
)

# Absolute confidence change
df["abs_confidence_change"] = df["confidence_change"].abs()

# Give priority to rules that:
# 1. Have strong testing confidence
# 2. Have high lift
# 3. Have small train-test difference

df["score"] = (
    df["test_confidence"] * 0.4
    + df["training_lift"] * 0.4
    - df["abs_confidence_change"] * 0.2
)

# Sort by score
df = df.sort_values(
    by="score",
    ascending=False
)

# Select best rules from each attack
final_rules = (
    df.groupby("attack")
      .head(3)
      .copy()
)

# Sort final results
final_rules = final_rules.sort_values(
    by=["attack", "score"],
    ascending=[True, False]
)

# Select useful columns
final_rules = final_rules[
    [
        "attack",
        "pattern",
        "training_support",
        "training_confidence",
        "training_lift",
        "test_support",
        "test_confidence",
        "confidence_change",
        "score"
    ]
]

# Round numerical values
numeric_columns = [
    "training_support",
    "training_confidence",
    "training_lift",
    "test_support",
    "test_confidence",
    "confidence_change",
    "score"
]

final_rules[numeric_columns] = final_rules[numeric_columns].round(4)

print("\n========== FINAL REPRESENTATIVE RULES ==========\n")
print(final_rules.to_string(index=False))

# Save
final_rules.to_csv(
    "final_representative_attack_rules.csv",
    index=False
)

print("\nSaved as: final_representative_attack_rules.csv")