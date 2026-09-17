import pandas as pd

# Load validated rules
df = pd.read_csv("attack_pattern_validation.csv")

# Calculate confidence change
df["confidence_change"] = (
    df["test_confidence"] - df["training_confidence"]
)

# Attack-wise summary
summary = (
    df.groupby("attack")
    .agg(
        number_of_rules=("attack", "count"),
        average_training_confidence=("training_confidence", "mean"),
        average_testing_confidence=("test_confidence", "mean"),
        average_lift=("training_lift", "mean"),
        average_confidence_change=("confidence_change", "mean")
    )
    .reset_index()
)

# Round values
summary["average_training_confidence"] = summary[
    "average_training_confidence"
].round(4)

summary["average_testing_confidence"] = summary[
    "average_testing_confidence"
].round(4)

summary["average_lift"] = summary[
    "average_lift"
].round(4)

summary["average_confidence_change"] = summary[
    "average_confidence_change"
].round(4)

# Sort by average lift
summary = summary.sort_values(
    by="average_lift",
    ascending=False
)

# Display
print("\n========== ATTACK-WISE SUMMARY ==========\n")
print(summary.to_string(index=False))

# Save
summary.to_csv(
    "attack_wise_summary.csv",
    index=False
)

print("\nSaved as: attack_wise_summary.csv")