"""
McAfee Data Pipeline - Silver → Gold ETL Job
Dataset: Threat Analytics (Aggregated)
Layer: Gold (Business-Ready)
"""

import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame

from pyspark.context import SparkContext
from pyspark.sql import functions as F
from pyspark.sql.window import Window

args = getResolvedOptions(sys.argv, [
    "JOB_NAME", "SOURCE_DATABASE", "TARGET_DATABASE",
    "ENVIRONMENT", "SILVER_BUCKET", "GOLD_BUCKET",
])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

ENV           = args["ENVIRONMENT"]
SILVER_BUCKET = args["SILVER_BUCKET"]
GOLD_BUCKET   = args["GOLD_BUCKET"]
SOURCE_DB     = args["SOURCE_DATABASE"]
TARGET_DB     = args["TARGET_DATABASE"]

print(f"[McAfee Pipeline] Starting Silver→Gold: threat-analytics | ENV={ENV}")


def read_silver(table_name: str):
    return glueContext.create_dynamic_frame.from_catalog(
        database=SOURCE_DB,
        table_name=table_name,
        transformation_ctx=f"read_{table_name}",
    ).toDF()


def build_daily_threat_summary(av_df):
    """Gold Table 1: Daily threat summary per customer"""
    return av_df.groupBy(
        "customer_id",
        "event_date",
        "country_code",
        "os_type",
    ).agg(
        F.count("*").alias("total_events"),
        F.countDistinct("device_id").alias("affected_devices"),
        F.countDistinct("threat_hash").alias("unique_threats"),
        F.sum(F.when(F.col("severity") == "CRITICAL", 1).otherwise(0)).alias("critical_count"),
        F.sum(F.when(F.col("severity") == "HIGH", 1).otherwise(0)).alias("high_count"),
        F.sum(F.when(F.col("severity") == "MEDIUM", 1).otherwise(0)).alias("medium_count"),
        F.sum(F.when(F.col("severity") == "LOW", 1).otherwise(0)).alias("low_count"),
        F.sum(F.when(F.col("action_taken") == "QUARANTINE", 1).otherwise(0)).alias("quarantined_count"),
        F.sum(F.when(F.col("action_taken") == "DELETE", 1).otherwise(0)).alias("deleted_count"),
        F.sum(F.when(F.col("action_taken") == "BLOCK", 1).otherwise(0)).alias("blocked_count"),
        F.avg("severity_score").alias("avg_severity_score"),
        F.max("severity_score").alias("max_severity_score"),
        F.collect_set("threat_category").alias("threat_categories_detected"),
        F.first("product_version").alias("product_version"),
    )


def build_threat_leaderboard(av_df):
    """Gold Table 2: Top threats globally"""
    return av_df.groupBy(
        "threat_name",
        "threat_hash",
        "threat_category",
        "detection_type",
    ).agg(
        F.count("*").alias("global_hit_count"),
        F.countDistinct("customer_id").alias("customers_affected"),
        F.countDistinct("device_id").alias("devices_affected"),
        F.countDistinct("country_code").alias("countries_affected"),
        F.max("severity").alias("max_severity"),
        F.max("severity_score").alias("max_severity_score"),
        F.min("event_timestamp").alias("first_seen"),
        F.max("event_timestamp").alias("last_seen"),
        F.collect_set("os_type").alias("os_types_affected"),
    ).withColumn(
        "threat_rank",
        F.dense_rank().over(Window.orderBy(F.desc("global_hit_count")))
    )


def build_hourly_detection_trend(av_df):
    """Gold Table 3: Hourly trend for real-time dashboards"""
    return av_df.groupBy(
        "event_date",
        "event_hour",
        "threat_category",
        "os_type",
        "country_code",
    ).agg(
        F.count("*").alias("detection_count"),
        F.countDistinct("device_id").alias("devices_count"),
        F.avg("severity_score").alias("avg_severity_score"),
        F.sum(F.when(F.col("severity_score") >= 3, 1).otherwise(0)).alias("high_critical_count"),
    )


def build_customer_risk_score(av_df):
    """Gold Table 4: Customer risk scoring (30-day rolling)"""
    w30 = Window.partitionBy("customer_id").orderBy("event_date") \
                .rangeBetween(-30, 0)

    daily = av_df.groupBy("customer_id", "event_date").agg(
        F.sum("severity_score").alias("daily_severity_sum"),
        F.count("*").alias("daily_events"),
        F.countDistinct("threat_hash").alias("daily_unique_threats"),
    )

    return daily.withColumn(
        "rolling_30d_severity",      F.sum("daily_severity_sum").over(w30)
    ).withColumn(
        "rolling_30d_events",        F.sum("daily_events").over(w30)
    ).withColumn(
        "rolling_30d_unique_threats",F.sum("daily_unique_threats").over(w30)
    ).withColumn(
        "risk_score",
        (F.col("rolling_30d_severity") * 0.5) +
        (F.col("rolling_30d_unique_threats") * 10) +
        (F.col("rolling_30d_events") * 0.1)
    ).withColumn(
        "risk_tier",
        F.when(F.col("risk_score") >= 500,  "CRITICAL")
         .when(F.col("risk_score") >= 200,  "HIGH")
         .when(F.col("risk_score") >= 50,   "MEDIUM")
         .otherwise("LOW")
    )


def write_gold_table(df, table_name, partition_cols=None):
    df = df \
        .withColumn("gold_processed_at", F.current_timestamp()) \
        .withColumn("environment", F.lit(ENV))

    gold_path = f"s3://{GOLD_BUCKET}/threat-analytics/{table_name}/"
    dyf = DynamicFrame.fromDF(df, glueContext, f"gold_{table_name}")

    sink = glueContext.getSink(
        path=gold_path,
        connection_type="s3",
        updateBehavior="UPDATE_IN_DATABASE",
        partitionKeys=partition_cols or [],
        compression="snappy",
        enableUpdateCatalog=True,
        transformation_ctx=f"write_gold_{table_name}",
    )
    sink.setCatalogInfo(catalogDatabase=TARGET_DB, catalogTableName=table_name)
    sink.setFormat("glueparquet")
    sink.writeFrame(dyf)
    print(f"[Gold] Written {df.count()} rows to {table_name}")


def main():
    av_df = read_silver("antivirus_events")

    # Build & write Gold tables in parallel (Spark handles DAG optimization)
    daily_summary   = build_daily_threat_summary(av_df)
    leaderboard     = build_threat_leaderboard(av_df)
    hourly_trend    = build_hourly_detection_trend(av_df)
    customer_risk   = build_customer_risk_score(av_df)

    write_gold_table(daily_summary,  "daily_threat_summary",   ["event_date"])
    write_gold_table(leaderboard,    "global_threat_leaderboard")
    write_gold_table(hourly_trend,   "hourly_detection_trend", ["event_date"])
    write_gold_table(customer_risk,  "customer_risk_scores",   ["event_date"])

    print("[McAfee Pipeline] Silver→Gold COMPLETE: threat-analytics")
    job.commit()


if __name__ == "__main__":
    main()
