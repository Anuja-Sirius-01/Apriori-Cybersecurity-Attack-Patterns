import pandas as pd

# Load dataset
df = pd.read_csv("UNSW_NB15_training-set.csv")

# -----------------------------------------
# Select important cybersecurity features
# -----------------------------------------

features = [
    "proto",
    "service",
    "state",
    "attack_cat"
]

data = df[features].copy()

# -----------------------------------------
# Keep common protocol values
# -----------------------------------------

common_protocols = [
    "tcp",
    "udp",
    "unas",
    "arp",
    "ospf",
    "sctp"
]

data = data[data["proto"].isin(common_protocols)]

# -----------------------------------------
# Keep common service values
# -----------------------------------------

common_services = [
    "-",
    "dns",
    "http",
    "smtp",
    "ftp-data",
    "ftp",
    "ssh",
    "pop3"
]

data = data[data["service"].isin(common_services)]

# -----------------------------------------
# Keep common states
# -----------------------------------------

common_states = [
    "INT",
    "FIN",
    "CON",
    "REQ"
]

data = data[data["state"].isin(common_states)]

# -----------------------------------------
# Create transaction items
# -----------------------------------------

transactions = []

for _, row in data.iterrows():

    transaction = [
        "proto_" + str(row["proto"]),
        "service_" + str(row["service"]),
        "state_" + str(row["state"]),
        "attack_" + str(row["attack_cat"])
    ]

    transactions.append(transaction)

# -----------------------------------------
# Display results
# -----------------------------------------

print("Original records:", len(df))
print("Records after filtering:", len(data))

print("\nFirst 10 transactions:")

for transaction in transactions[:10]:
    print(transaction)

print("\nTotal transactions:", len(transactions))