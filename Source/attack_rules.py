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

transaction_array = te.fit(transactions).transform(transactions)

transaction_df = pd.DataFrame(
    transaction_array,
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
# 7. Association rules
# ==========================================

rules = association_rules(
    frequent_itemsets,
    metric="confidence",
    min_threshold=0.30
)

# ==========================================
# 8. Keep only rules predicting attacks
# ==========================================

attack_rules = rules[
    rules["consequents"].apply(
        lambda x: any(str(item).startswith("attack_") for item in x)
    )
].copy()

# Remove rules where attack is already present
# in the antecedent
attack_rules = attack_rules[
    ~attack_rules["antecedents"].apply(
        lambda x: any(str(item).startswith("attack_") for item in x)
    )
]

# ==========================================
# 9. Sort by lift
# ==========================================

attack_rules = attack_rules.sort_values(
    by="lift",
    ascending=False
)

# ==========================================
# 10. Display results
# ==========================================

print("\nTotal attack-related rules:",
      len(attack_rules))

print("\nTop 20 cybersecurity attack rules:\n")

print(
    attack_rules[
        [
            "antecedents",
            "consequents",
            "support",
            "confidence",
            "lift"
        ]
    ].head(20).to_string(index=False)
)

# ==========================================
# 11. Save results
# ==========================================

attack_rules.to_csv(
    "cybersecurity_attack_rules.csv",
    index=False
)

print("\nRules saved to:")
print("cybersecurity_attack_rules.csv")

# ==========================================
# FINAL RESEARCH ATTACK PATTERNS
# ==========================================

# Keep only rules with ONE attack category as consequent
research_rules = attack_rules[
    attack_rules["consequents"].apply(
        lambda x: len(x) == 1 and
        next(iter(x)).startswith("attack_")
    )
].copy()

# Remove rules where attack is already in antecedent
research_rules = research_rules[
    research_rules["antecedents"].apply(
        lambda x: not any(
            str(item).startswith("attack_")
            for item in x
        )
    )
].copy()

# Create attack column
research_rules["attack"] = research_rules["consequents"].apply(
    lambda x: next(iter(x)).replace("attack_", "")
)

# Remove NORMAL traffic
research_rules = research_rules[
    research_rules["attack"] != "Normal"
].copy()

# Convert antecedents into readable pattern
research_rules["pattern"] = research_rules["antecedents"].apply(
    lambda x: " + ".join(
        sorted(
            item.replace("proto_", "Protocol=")
                .replace("service_", "Service=")
                .replace("state_", "State=")
            for item in x
        )
    )
)

# Remove exact duplicate patterns
research_rules = research_rules.drop_duplicates(
    subset=["pattern", "attack"]
)

# Apply minimum thresholds
research_rules = research_rules[
    (research_rules["support"] >= 0.005) &
    (research_rules["confidence"] >= 0.30)
]

# Sort by lift
research_rules = research_rules.sort_values(
    by=["lift", "confidence", "support"],
    ascending=False
)

# ==========================================
# DISPLAY
# ==========================================

print("\n==========================================")
print("FINAL RESEARCH ATTACK PATTERNS")
print("==========================================")

print(
    research_rules[
        [
            "pattern",
            "attack",
            "support",
            "confidence",
            "lift"
        ]
    ].head(15).to_string(index=False)
)

print("\nTotal research attack patterns:",
      len(research_rules))

# ==========================================
# SAVE
# ==========================================

research_rules[
    [
        "pattern",
        "attack",
        "support",
        "confidence",
        "lift"
    ]
].to_csv(
    "research_attack_patterns.csv",
    index=False
)

print("\nSaved as:")
print("research_attack_patterns.csv")