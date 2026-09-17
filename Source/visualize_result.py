import pandas as pd
import matplotlib.pyplot as plt

# ==========================================
# LOAD VALIDATION RESULTS
# ==========================================

df = pd.read_csv("attack_pattern_validation.csv")

# Keep only the strongest representative rules
df = df.sort_values(
    by="training_lift",
    ascending=False
).head(10).copy()

# Short labels
df["label"] = (
    df["attack"] + ": " + df["pattern"]
)

# ==========================================
# FIGURE 1
# TRAINING VS TESTING CONFIDENCE
# ==========================================

plt.figure(figsize=(12, 7))

x = range(len(df))

plt.plot(
    x,
    df["training_confidence"],
    marker="o",
    label="Training Confidence"
)

plt.plot(
    x,
    df["test_confidence"],
    marker="o",
    label="Testing Confidence"
)

plt.xticks(
    x,
    df["label"],
    rotation=60,
    ha="right"
)

plt.ylabel("Confidence")
plt.title(
    "Training vs Testing Confidence of Attack Patterns"
)

plt.legend()
plt.tight_layout()

plt.savefig(
    "training_vs_testing_confidence.png",
    dpi=300
)

plt.show()


# ==========================================
# FIGURE 2
# LIFT
# ==========================================

plt.figure(figsize=(12, 7))

plt.bar(
    df["label"],
    df["training_lift"]
)

plt.xticks(
    rotation=60,
    ha="right"
)

plt.ylabel("Lift")
plt.title(
    "Association Strength of Cybersecurity Attack Patterns"
)

plt.tight_layout()

plt.savefig(
    "attack_pattern_lift.png",
    dpi=300
)

plt.show()


# ==========================================
# FIGURE 3
# CONFIDENCE CHANGE
# ==========================================

plt.figure(figsize=(12, 7))

plt.bar(
    df["label"],
    df["confidence_change"]
)

plt.axhline(
    0,
    linewidth=1
)

plt.xticks(
    rotation=60,
    ha="right"
)

plt.ylabel("Change in Confidence")
plt.title(
    "Change in Rule Confidence from Training to Testing"
)

plt.tight_layout()

plt.savefig(
    "confidence_change.png",
    dpi=300
)

plt.show()


# ==========================================
# SAVE TOP VALIDATED RULES
# ==========================================

df.to_csv(
    "top_validated_attack_patterns.csv",
    index=False
)

print("\n==========================================")
print("VISUALIZATION COMPLETE")
print("==========================================")

print("\nGenerated:")
print("1. training_vs_testing_confidence.png")
print("2. attack_pattern_lift.png")
print("3. confidence_change.png")
print("4. top_validated_attack_patterns.csv")