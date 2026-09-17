import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori, association_rules

# ==========================================
# 1. Load dataset
# ==========================================

df = pd.read_csv("UNSW_NB15_training-set.csv")

# ==========================================
# 2. Select features
# ==========================================

features = [
    "proto",
    "service",
    "state",
    "attack_cat"
]

data = df[features].copy()

# ==========================================
# 3. Filter common values
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

data = data[
    data["proto"].isin(common_protocols) &
    data["service"].isin(common_services) &
    data["state"].isin(common_states)
]

# ==========================================
# 4. Create transactions
# ==========================================

transactions = []

for _, row in data.iterrows():

    transaction = [
        "proto_" + str(row["proto"]),
        "service_" + str(row["service"]),
        "state_" + str(row["state"]),
        "attack_" + str(row["attack_cat"])
    ]

    transactions.append(transaction)

# ==========================================
# 5. One-hot encoding
# ==========================================

te = TransactionEncoder()

encoded = te.fit(transactions).transform(transactions)

transaction_df = pd.DataFrame(
    encoded,
    columns=te.columns_
)

# ==========================================
# 6. Apriori
# ==========================================

frequent_itemsets = apriori(
    transaction_df,
    min_support=0.005,
    use_colnames=True
)

# ==========================================
# 7. Generate rules
# ==========================================

rules = association_rules(
    frequent_itemsets,
    metric="confidence",
    min_threshold=0.30
)

# ==========================================
# 8. Keep rules where consequent
#    contains an actual attack
# ==========================================

attack_categories = [
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Analysis",
    "Backdoor",
    "Shellcode",
    "Worms"
]

attack_rules = rules[
    rules["consequents"].apply(
        lambda x: any(
            item in [
                "attack_" + category
                for category in attack_categories
            ]
            for item in x
        )
    )
].copy()

# Remove rules where attack is already in antecedent
attack_rules = attack_rules[
    ~attack_rules["antecedents"].apply(
        lambda x: any(
            str(item).startswith("attack_")
            for item in x
        )
    )
]

# ==========================================
# 9. Remove Normal-related consequents
# ==========================================

attack_rules = attack_rules[
    ~attack_rules["consequents"].apply(
        lambda x: "attack_Normal" in x
    )
]

# ==========================================
# 10. Sort by Lift
# ==========================================

attack_rules = attack_rules.sort_values(
    by="lift",
    ascending=False
)

# ==========================================
# 11. Display strongest rules
# ==========================================

print("\nTotal attack rules:", len(attack_rules))

print("\nTop 30 attack-pattern rules:\n")

print(
    attack_rules[
        [
            "antecedents",
            "consequents",
            "support",
            "confidence",
            "lift"
        ]
    ].head(30).to_string(index=False)
)

# ==========================================
# 12. Save results
# ==========================================

attack_rules.to_csv(
    "final_attack_pattern_rules.csv",
    index=False
)

print("\nResults saved as:")
print("final_attack_pattern_rules.csv")

# ==========================================
# Keep only single attack as consequent
# ==========================================

single_attack_rules = attack_rules[
    attack_rules["consequents"].apply(
        lambda x: len(x) == 1
    )
].copy()

# Keep only actual attack categories
single_attack_rules = single_attack_rules[
    single_attack_rules["consequents"].apply(
        lambda x: any(
            str(item).startswith("attack_")
            for item in x
        )
    )
]

# Sort by lift
single_attack_rules = single_attack_rules.sort_values(
    by=["lift", "confidence", "support"],
    ascending=False
)

# Display
print("\n==========================================")
print("FINAL SINGLE-ATTACK ASSOCIATION RULES")
print("==========================================")

print(
    single_attack_rules[
        [
            "antecedents",
            "consequents",
            "support",
            "confidence",
            "lift"
        ]
    ].head(30).to_string(index=False)
)

print("\nTotal single-attack rules:",
      len(single_attack_rules))

# Save
single_attack_rules.to_csv(
    "single_attack_association_rules.csv",
    index=False
)

print("\nSaved as:")
print("single_attack_association_rules.csv")