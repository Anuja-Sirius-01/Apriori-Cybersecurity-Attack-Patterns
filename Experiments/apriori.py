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

print("Total transactions:", len(transactions))

# ==========================================
# 5. One-hot encode transactions
# ==========================================

te = TransactionEncoder()

transaction_array = te.fit(transactions).transform(transactions)

transaction_df = pd.DataFrame(
    transaction_array,
    columns=te.columns_
)

print("\nTransaction matrix shape:")
print(transaction_df.shape)

# ==========================================
# 6. Apply Apriori
# ==========================================

frequent_itemsets = apriori(
    transaction_df,
    min_support=0.01,
    use_colnames=True
)

print("\nFrequent itemsets:")
print(frequent_itemsets)

# ==========================================
# 7. Generate association rules
# ==========================================

rules = association_rules(
    frequent_itemsets,
    metric="confidence",
    min_threshold=0.50
)

# ==========================================
# 8. Sort rules by lift
# ==========================================

rules = rules.sort_values(
    by="lift",
    ascending=False
)

print("\nTop 20 Association Rules:")
print(
    rules[
        [
            "antecedents",
            "consequents",
            "support",
            "confidence",
            "lift"
        ]
    ].head(20)
)