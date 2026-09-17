import pandas as pd

# Load validation results
rules = pd.read_csv("attack_pattern_validation.csv")

# Load original testing dataset
test = pd.read_csv("UNSW_NB15_testing-set.csv")

# Apply the SAME filtering used during the research
common_protocols = ["tcp", "udp", "unas", "arp", "ospf", "sctp"]
common_services = ["-", "dns", "http", "smtp", "ftp-data", "ftp", "ssh", "pop3"]
common_states = ["INT", "FIN", "CON", "REQ"]

test = test[
    test["proto"].isin(common_protocols)
    & test["service"].isin(common_services)
    & test["state"].isin(common_states)
].copy()

# Calculate attack prevalence in testing data
attack_support = (
    test["attack_cat"]
    .value_counts(normalize=True)
    .to_dict()
)

# Map attack prevalence to each rule
rules["test_attack_support"] = rules["attack"].map(
    attack_support
)

# Calculate testing lift
rules["test_lift"] = (
    rules["test_confidence"]
    / rules["test_attack_support"]
)

# Calculate change in lift
rules["lift_change"] = (
    rules["test_lift"]
    - rules["training_lift"]
)

# Round values
columns = [
    "training_confidence",
    "test_confidence",
    "training_lift",
    "test_attack_support",
    "test_lift",
    "lift_change"
]

rules[columns] = rules[columns].round(4)

# Select useful columns
results = rules[
    [
        "attack",
        "pattern",
        "training_confidence",
        "test_confidence",
        "training_lift",
        "test_attack_support",
        "test_lift",
        "lift_change"
    ]
]

# Sort by testing lift
results = results.sort_values(
    by="test_lift",
    ascending=False
)

print("\n========== TRAINING vs TESTING LIFT ==========\n")
print(results.to_string(index=False))

# Save
results.to_csv(
    "training_testing_lift_comparison.csv",
    index=False
)

print("\nSaved as: training_testing_lift_comparison.csv")