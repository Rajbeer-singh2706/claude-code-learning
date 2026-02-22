"""
McAfee Data Pipeline - Bronze → Silver ETL Job
Dataset: Antivirus Events
Layer: Silver (Cleansed & Validated)
"""

import sys
import json
import re
from datetime import datetime, timezone

from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame

from pyspark.context import SparkContext
from pyspark.sql import SparkSession, functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# ── Initialization ────────────────────────────────────
args = getResolvedOptions(sys.argv, [
    "JOB_NAME",
    "SOURCE_DATABASE",
    "TARGET_DATABASE",
    "ENVIRONMENT",
    "BRONZE_BUCKET",
    "SILVER_BUCKET",
])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

ENV          = args["ENVIRONMENT"]
BRONZE_BUCKET = args["BRONZE_BUCKET"]
SILVER_BUCKET = args["SILVER_BUCKET"]
SOURCE_DB     = args["SOURCE_DATABASE"]
TARGET_DB     = args["TARGET_DATABASE"]

print(f"[McAfee Pipeline] Starting Bronze→Silver: antivirus-events | ENV={ENV}")


# ── Schema Definition ─────────────────────────────────
ANTIVIRUS_SCHEMA = StructType([
    StructField("event_id",           StringType(),    False),
    StructField("device_id",          StringType(),    False),
    StructField("customer_id",        StringType(),    False),
    StructField("event_timestamp",    TimestampType(), False),
    StructField("threat_name",        StringType(),    True),
    StructField("threat_hash",        StringType(),    True),
    StructField("severity",           StringType(),    True),
    StructField("action_taken",       StringType(),    True),
    StructField("detection_type",     StringType(),    True),
    StructField("file_path",          StringType(),    True),
    StructField("file_size_bytes",    LongType(),      True),
    StructField("os_type",            StringType(),    True),
    StructField("os_version",         StringType(),    True),
    StructField("product_version",    StringType(),    True),
    StructField("country_code",       StringType(),    True),
    StructField("ip_address",         StringType(),    True),
    StructField("kafka_partition",    IntegerType(),   True),
    StructField("kafka_offset",       LongType(),      True),
    StructField("ingestion_timestamp", TimestampType(), True),
])

VALID_SEVERITIES      = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_ACTIONS         = {"QUARANTINE", "DELETE", "ALLOW", "BLOCK", "CLEAN"}
VALID_DETECTION_TYPES = {"SIGNATURE", "HEURISTIC", "BEHAVIORAL", "MACHINE_LEARNING", "REPUTATION"}
VALID_OS_TYPES        = {"WINDOWS", "MACOS", "LINUX", "ANDROID", "IOS"}


# ── Read from Bronze ──────────────────────────────────
def read_bronze() -> DynamicFrame:
    return glueContext.create_dynamic_frame.from_catalog(
        database=SOURCE_DB,
        table_name="antivirus_events",
        transformation_ctx="read_bronze_av",
        additional_options={"useS3ListImplementation": True},
    )


# ── Validation & Cleansing ────────────────────────────
def validate_and_cleanse(df):
    print(f"[Bronze] Row count before cleansing: {df.count()}")

    # Standardise string columns
    string_cols = ["severity", "action_taken", "detection_type", "os_type"]
    for col in string_cols:
        df = df.withColumn(col, F.upper(F.trim(F.col(col))))

    # Validate event_id (must be UUID or 32-36 char hex)
    df = df.withColumn(
        "is_valid_event_id",
        F.col("event_id").rlike(r"^[0-9a-fA-F-]{32,36}$")
    )

    # Validate enums
    df = df.withColumn("is_valid_severity",   F.col("severity").isin(list(VALID_SEVERITIES)))
    df = df.withColumn("is_valid_action",     F.col("action_taken").isin(list(VALID_ACTIONS)))
    df = df.withColumn("is_valid_detection",  F.col("detection_type").isin(list(VALID_DETECTION_TYPES)))
    df = df.withColumn("is_valid_os",         F.col("os_type").isin(list(VALID_OS_TYPES)))

    # Nullability checks on required fields
    required_cols = ["event_id", "device_id", "customer_id", "event_timestamp"]
    null_checks = [F.col(c).isNotNull() for c in required_cols]
    df = df.withColumn("is_not_null", F.reduce(lambda a, b: a & b, null_checks))

    # Future timestamp check
    df = df.withColumn(
        "is_valid_timestamp",
        (F.col("event_timestamp") <= F.current_timestamp()) &
        (F.col("event_timestamp") >= F.lit("2010-01-01").cast(TimestampType()))
    )

    # Composite validity flag
    df = df.withColumn(
        "is_valid_record",
        F.col("is_valid_event_id") &
        F.col("is_valid_severity") &
        F.col("is_valid_action") &
        F.col("is_valid_detection") &
        F.col("is_not_null") &
        F.col("is_valid_timestamp")
    )

    # Separate valid / invalid
    valid_df   = df.filter(F.col("is_valid_record"))
    invalid_df = df.filter(~F.col("is_valid_record"))

    print(f"[Silver] Valid rows: {valid_df.count()}, Invalid rows: {invalid_df.count()}")
    return valid_df, invalid_df


# ── Enrichment & Transformations ──────────────────────
def enrich(df):
    # Deduplicate by event_id, keep latest ingestion
    w = Window.partitionBy("event_id").orderBy(F.desc("ingestion_timestamp"))
    df = df.withColumn("row_num", F.row_number().over(w)).filter(F.col("row_num") == 1).drop("row_num")

    # Mask PII - partial IP masking
    df = df.withColumn(
        "ip_address_masked",
        F.regexp_replace(F.col("ip_address"), r"\.\d+$", ".xxx")
    ).drop("ip_address")

    # Derived columns
    df = df.withColumn("event_date", F.to_date(F.col("event_timestamp")))
    df = df.withColumn("event_hour", F.hour(F.col("event_timestamp")))
    df = df.withColumn("event_year",  F.year(F.col("event_timestamp")))
    df = df.withColumn("event_month", F.month(F.col("event_timestamp")))

    # Severity score (numeric)
    df = df.withColumn(
        "severity_score",
        F.when(F.col("severity") == "CRITICAL", 4)
         .when(F.col("severity") == "HIGH",     3)
         .when(F.col("severity") == "MEDIUM",   2)
         .when(F.col("severity") == "LOW",      1)
         .otherwise(0)
    )

    # Threat category from threat_name prefix
    df = df.withColumn(
        "threat_category",
        F.when(F.lower(F.col("threat_name")).contains("ransomware"), "RANSOMWARE")
         .when(F.lower(F.col("threat_name")).contains("trojan"),     "TROJAN")
         .when(F.lower(F.col("threat_name")).contains("spyware"),    "SPYWARE")
         .when(F.lower(F.col("threat_name")).contains("adware"),     "ADWARE")
         .when(F.lower(F.col("threat_name")).contains("worm"),       "WORM")
         .when(F.lower(F.col("threat_name")).contains("virus"),      "VIRUS")
         .otherwise("OTHER")
    )

    # Audit columns
    df = df.withColumn("silver_processed_at", F.current_timestamp())
    df = df.withColumn("pipeline_version", F.lit("2.0.0"))
    df = df.withColumn("environment", F.lit(ENV))

    # Drop validation helper columns
    validation_cols = [c for c in df.columns if c.startswith("is_valid_") or c == "is_not_null"]
    df = df.drop(*validation_cols)

    return df


# ── Write to Silver ───────────────────────────────────
def write_silver(valid_df, invalid_df):
    silver_path = f"s3://{SILVER_BUCKET}/antivirus-events/"
    quarantine_path = f"s3://{SILVER_BUCKET}/_quarantine/antivirus-events/"

    # Write valid records as Parquet partitioned by year/month/day
    valid_dyf = DynamicFrame.fromDF(valid_df, glueContext, "valid_av_silver")
    sink = glueContext.getSink(
        path=silver_path,
        connection_type="s3",
        updateBehavior="UPDATE_IN_DATABASE",
        partitionKeys=["event_year", "event_month", "event_date"],
        compression="snappy",
        enableUpdateCatalog=True,
        transformation_ctx="write_silver_av",
    )
    sink.setCatalogInfo(catalogDatabase=TARGET_DB, catalogTableName="antivirus_events")
    sink.setFormat("glueparquet")
    sink.writeFrame(valid_dyf)

    # Write invalid records to quarantine
    if invalid_df.count() > 0:
        invalid_df \
            .withColumn("quarantine_reason", F.lit("VALIDATION_FAILURE")) \
            .withColumn("quarantine_ts", F.current_timestamp()) \
            .write \
            .mode("append") \
            .parquet(quarantine_path)
        print(f"[Quarantine] Written {invalid_df.count()} invalid records to {quarantine_path}")


# ── Main ──────────────────────────────────────────────
def main():
    bronze_dyf     = read_bronze()
    bronze_df      = bronze_dyf.toDF()

    valid_df, invalid_df = validate_and_cleanse(bronze_df)
    enriched_df    = enrich(valid_df)

    write_silver(enriched_df, invalid_df)
    print(f"[McAfee Pipeline] Bronze→Silver COMPLETE | Processed {enriched_df.count()} records")
    job.commit()


if __name__ == "__main__":
    main()
