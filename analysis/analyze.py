"""
analyze.py
----------
PySpark analysis of the captured honeypot logs.

*** READ THIS FIRST — the whole point of the file ***
You already know SQL. PySpark is basically SQL with a Python accent.
Below, EVERY analysis is shown TWICE:
    (A) the DataFrame API  — the "Pythonic" way
    (B) spark.sql(...)     — literally the SQL you already write
Pick whichever feels natural. They produce the identical result.

Run this on Databricks Free Edition (Spark is already installed there) — just
paste these functions into a notebook. Point INPUT_PATH at your Blob container.
"""

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

spark = SparkSession.builder.appName("honeypot").getOrCreate()

INPUT_PATH = "abfss://raw-logs@<youraccount>.dfs.core.windows.net/*.json"


def load_events(path=INPUT_PATH):
    """Spark reads JSON-lines files natively — one line becomes one row.

    A Spark DataFrame is just a table. `df.printSchema()` shows its columns,
    like DESCRIBE TABLE. `df.show()` is like SELECT * ... LIMIT 20.
    """
    df = spark.read.json(path)
    df.createOrReplaceTempView("events")  # register it so spark.sql() can see it
    return df


def top_source_ips(df, n=20):
    """Which IPs attacked us the most?"""

    # (A) DataFrame API — .groupBy().count() == GROUP BY ... COUNT(*)
    result = (
        df.groupBy("src_ip")
        .count()
        .orderBy(F.col("count").desc())
        .limit(n)
    )

    # (B) The exact same thing in SQL:
    # result = spark.sql("""
    #     SELECT src_ip, COUNT(*) AS attempts
    #     FROM events
    #     GROUP BY src_ip
    #     ORDER BY attempts DESC
    #     LIMIT 20
    # """)

    return result


def top_credentials(df, n=25):
    """Most-tried username/password pairs — great dashboard content."""

    logins = df.filter(F.col("eventid").startswith("cowrie.login"))

    # (A) DataFrame API
    result = (
        logins.groupBy("username", "password")
        .count()
        .orderBy(F.col("count").desc())
        .limit(n)
    )

    # (B) SQL equivalent
    # result = spark.sql("""
    #     SELECT username, password, COUNT(*) AS tries
    #     FROM events
    #     WHERE eventid LIKE 'cowrie.login%'
    #     GROUP BY username, password
    #     ORDER BY tries DESC
    #     LIMIT 25
    # """)

    return result


def attacks_per_day(df):
    """Trend over time — for the line chart on the dashboard.

    Cowrie's 'timestamp' is an ISO string; to_date() parses it, same as
    CAST(timestamp AS DATE) in SQL.
    """
    result = (
        df.withColumn("day", F.to_date("timestamp"))
        .groupBy("day")
        .count()
        .orderBy("day")
    )
    return result


def top_commands(df, n=20):
    """What commands did attackers try to run once 'inside'?

    These map to MITRE ATT&CK techniques — a strong CV talking point.
    Cowrie logs executed commands as eventid 'cowrie.command.input',
    with the text in the 'input' column.
    """
    return (
        df.filter(F.col("eventid") == "cowrie.command.input")
        .groupBy("input")
        .count()
        .orderBy(F.col("count").desc())
        .limit(n)
    )


def save_table(df, name):
    """Write results as Parquet so the dashboard can read them cheaply.

    Parquet is a compressed columnar file format — think of it as a
    'saved query result' that's fast to re-read. Delta (Databricks' default)
    is Parquet plus versioning; either is fine to start.
    """
    df.write.mode("overwrite").parquet(f"abfss://gold@<youraccount>.dfs.core.windows.net/{name}")


if __name__ == "__main__":
    df = load_events()
    df.printSchema()               # see what columns Cowrie gives you
    top_source_ips(df).show()
    top_credentials(df).show()
    attacks_per_day(df).show()
