import pandas as pd

# Load representative rules
representative = pd.read_csv(
    "representative_attack_rules.csv"
)

# Load lift comparison
validation = pd.read_csv(
    "training_testing_lift_comparison.csv"
)

# Merge using attack + pattern
final = representative.merge(
    validation[
        [
            "attack",
            "pattern",
            "test_attack_support",
            "test_lift",
            "lift_change"
        ]
    ],
    on=["attack", "pattern"],
    how="left"
)

# Select final research columns
final = final[
    [
        "attack",
        "pattern",
        "training_support",
        "test_support",
        "training_confidence",
        "test_confidence",
        "training_lift",
        "test_lift",
        "confidence_change",
        "lift_change"
    ]
]

# Remove duplicate rows
final = final.drop_duplicates()

# Sort by testing lift
final = final.sort_values(
    by="test_lift",
    ascending=False
)

# Round numerical values
numeric_columns = [
    "training_support",
    "test_support",
    "training_confidence",
    "test_confidence",
    "training_lift",
    "test_lift",
    "confidence_change",
    "lift_change"
]

final[numeric_columns] = (
    final[numeric_columns].round(4)
)

print("\n========== FINAL RESEARCH RESULTS ==========\n")
print(final.to_string(index=False))

print(
    "\nTotal final representative rules:",
    len(final)
)

# Save
final.to_csv(
    "FINAL_RESEARCH_RESULTS.csv",
    index=False
)

print("\nSaved as: FINAL_RESEARCH_RESULTS.csv")