import pandas as pd

# ==========================================
# 1. LOAD DATA
# ==========================================

test_df = pd.read_csv("UNSW_NB15_testing-set.csv")

rules_df = pd.read_csv(
    "research_attack_patterns.csv"
)

print("Testing dataset shape:", test_df.shape)
print("Number of discovered rules:", len(rules_df))


# ==========================================
# 2. FILTER SAME VALUES USED IN TRAINING
# ==========================================

common_protocols = [
    "tcp", "udp", "unas", "arp", "ospf", "sctp"
]

common_services = [
    "-", "dns", "http", "smtp",
    "ftp-data", "ftp", "ssh", "pop3"
]

common_states = [
    "INT", "FIN", "CON", "REQ"
]

test_data = test_df[
    test_df["proto"].isin(common_protocols) &
    test_df["service"].isin(common_services) &
    test_df["state"].isin(common_states)
].copy()

print(
    "Testing records after filtering:",
    len(test_data)
)


# ==========================================
# 3. VALIDATE EACH RULE
# ==========================================

results = []

for _, rule in rules_df.iterrows():

    pattern = rule["pattern"]
    attack = rule["attack"]

    # --------------------------------------
    # Extract conditions
    # --------------------------------------

    conditions = pattern.split(" + ")

    mask = pd.Series(
        True,
        index=test_data.index
    )

    for condition in conditions:

        if condition.startswith("Protocol="):
            value = condition.replace(
                "Protocol=", ""
            )

            mask &= (
                test_data["proto"] == value
            )

        elif condition.startswith("Service="):
            value = condition.replace(
                "Service=", ""
            )

            mask &= (
                test_data["service"] == value
            )

        elif condition.startswith("State="):
            value = condition.replace(
                "State=", ""
            )

            mask &= (
                test_data["state"] == value
            )

    # --------------------------------------
    # Transactions matching antecedent
    # --------------------------------------

    matching_rows = test_data[mask]

    antecedent_count = len(matching_rows)

    # --------------------------------------
    # Matching antecedent + attack
    # --------------------------------------

    attack_matches = matching_rows[
        matching_rows["attack_cat"].astype(str).str.strip()
        == attack
    ]

    attack_count = len(attack_matches)

    # --------------------------------------
    # Test support
    # --------------------------------------

    test_support = (
        attack_count / len(test_data)
        if len(test_data) > 0 else 0
    )

    # --------------------------------------
    # Test confidence
    # --------------------------------------

    test_confidence = (
        attack_count / antecedent_count
        if antecedent_count > 0 else 0
    )

    # --------------------------------------
    # Compare confidence
    # --------------------------------------

    confidence_change = (
        test_confidence - rule["confidence"]
    )

    # --------------------------------------
    # Validation status
    # --------------------------------------

    if antecedent_count == 0:
        validation = "Not observed"

    elif attack_count == 0:
        validation = "Not supported"

    else:
        validation = "Observed"

    # --------------------------------------
    # Store result
    # --------------------------------------

    results.append({
        "pattern": pattern,
        "attack": attack,
        "training_support": rule["support"],
        "training_confidence": rule["confidence"],
        "training_lift": rule["lift"],
        "test_antecedent_count": antecedent_count,
        "test_attack_count": attack_count,
        "test_support": test_support,
        "test_confidence": test_confidence,
        "confidence_change": confidence_change,
        "validation": validation
    })


# ==========================================
# 4. CREATE RESULT DATAFRAME
# ==========================================

validation_df = pd.DataFrame(results)


# ==========================================
# 5. SORT BY TEST CONFIDENCE
# ==========================================

validation_df = validation_df.sort_values(
    by=[
        "validation",
        "test_confidence"
    ],
    ascending=[True, False]
)


# ==========================================
# 6. DISPLAY RESULTS
# ==========================================

print("\n==========================================")
print("TEST SET VALIDATION RESULTS")
print("==========================================")

print(
    validation_df[
        [
            "pattern",
            "attack",
            "training_confidence",
            "training_lift",
            "test_support",
            "test_confidence",
            "confidence_change",
            "validation"
        ]
    ].to_string(index=False)
)


# ==========================================
# 7. VALIDATION SUMMARY
# ==========================================

total_rules = len(validation_df)

observed_rules = len(
    validation_df[
        validation_df["validation"] == "Observed"
    ]
)

not_supported = len(
    validation_df[
        validation_df["validation"] == "Not supported"
    ]
)

not_observed = len(
    validation_df[
        validation_df["validation"] == "Not observed"
    ]
)

print("\n==========================================")
print("VALIDATION SUMMARY")
print("==========================================")

print("Total rules:", total_rules)
print("Observed rules:", observed_rules)
print("Not supported:", not_supported)
print("Not observed:", not_observed)

if total_rules > 0:

    validation_rate = (
        observed_rules / total_rules
    ) * 100

    print(
        "Pattern observation rate:",
        round(validation_rate, 2),
        "%"
    )


# ==========================================
# 8. SAVE VALIDATION RESULTS
# ==========================================

validation_df.to_csv(
    "attack_pattern_validation.csv",
    index=False
)

print("\nSaved as:")
print("attack_pattern_validation.csv")