import pandas as pd

# Load validated rules
df = pd.read_csv("attack_pattern_validation.csv")

# Confidence change
df["confidence_change"] = (
    df["test_confidence"] - df["training_confidence"]
)

df["abs_change"] = df["confidence_change"].abs()

# Number of conditions in the pattern
df["pattern_length"] = df["pattern"].apply(
    lambda x: len(x.split(" + "))
)

# Sort:
# 1. Attack
# 2. Stronger lift
# 3. Higher testing confidence
# 4. Smaller train-test difference
# 5. Simpler pattern
df = df.sort_values(
    by=[
        "attack",
        "training_lift",
        "test_confidence",
        "abs_change",
        "pattern_length"
    ],
    ascending=[
        True,
        False,
        False,
        True,
        True
    ]
)

# Keep the strongest rule for each attack + similar strength family
selected = []

for attack in df["attack"].unique():

    attack_df = df[df["attack"] == attack].copy()

    # Select rules with different pattern lengths,
    # but avoid adding a rule if a simpler rule has
    # almost identical performance.

    chosen = []

    for _, row in attack_df.iterrows():

        redundant = False

        for existing in chosen:

            lift_difference = abs(
                row["training_lift"] -
                existing["training_lift"]
            )

            confidence_difference = abs(
                row["test_confidence"] -
                existing["test_confidence"]
            )

            # Treat nearly identical rules as redundant
            if (
                lift_difference < 0.05
                and confidence_difference < 0.02
            ):
                redundant = True
                break

        if not redundant:
            chosen.append(row)

    selected.extend(chosen[:3])

# Convert back to dataframe
final_rules = pd.DataFrame(selected)

# Sort by attack and lift
final_rules = final_rules.sort_values(
    by=["attack", "training_lift"],
    ascending=[True, False]
)

# Select columns for research
final_rules = final_rules[
    [
        "attack",
        "pattern",
        "training_support",
        "training_confidence",
        "training_lift",
        "test_support",
        "test_confidence",
        "confidence_change"
    ]
]

# Round values
numeric_columns = [
    "training_support",
    "training_confidence",
    "training_lift",
    "test_support",
    "test_confidence",
    "confidence_change"
]

final_rules[numeric_columns] = (
    final_rules[numeric_columns].round(4)
)

print("\n========== REPRESENTATIVE ATTACK RULES ==========\n")
print(final_rules.to_string(index=False))

print(
    "\nTotal representative rules:",
    len(final_rules)
)

# Save
final_rules.to_csv(
    "representative_attack_rules.csv",
    index=False
)

print("\nSaved as: representative_attack_rules.csv")