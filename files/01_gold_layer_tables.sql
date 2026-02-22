-- ============================================================
-- McAfee Data Warehouse - Redshift DDL
-- Gold Layer Tables + Distribution/Sort Keys
-- ============================================================

-- Schema creation
CREATE SCHEMA IF NOT EXISTS gold AUTHORIZATION etl_admin;
CREATE SCHEMA IF NOT EXISTS silver AUTHORIZATION etl_admin;
CREATE SCHEMA IF NOT EXISTS staging AUTHORIZATION etl_admin;

GRANT USAGE ON SCHEMA gold    TO GROUP reporting_users;
GRANT USAGE ON SCHEMA silver  TO GROUP etl_users;
GRANT USAGE ON SCHEMA staging TO GROUP etl_users;


-- ── GOLD: Daily Threat Summary ────────────────────────────
CREATE TABLE IF NOT EXISTS gold.daily_threat_summary (
    customer_id               VARCHAR(50)     NOT NULL,
    event_date                DATE            NOT NULL,
    country_code              CHAR(2),
    os_type                   VARCHAR(20),
    total_events              BIGINT          DEFAULT 0,
    affected_devices          INTEGER         DEFAULT 0,
    unique_threats            INTEGER         DEFAULT 0,
    critical_count            INTEGER         DEFAULT 0,
    high_count                INTEGER         DEFAULT 0,
    medium_count              INTEGER         DEFAULT 0,
    low_count                 INTEGER         DEFAULT 0,
    quarantined_count         INTEGER         DEFAULT 0,
    deleted_count             INTEGER         DEFAULT 0,
    blocked_count             INTEGER         DEFAULT 0,
    avg_severity_score        DECIMAL(5,2),
    max_severity_score        INTEGER,
    product_version           VARCHAR(20),
    gold_processed_at         TIMESTAMP       DEFAULT GETDATE(),
    environment               VARCHAR(10)
)
DISTSTYLE KEY
DISTKEY (customer_id)
SORTKEY (event_date, customer_id)
;

-- ── GOLD: Global Threat Leaderboard ──────────────────────
CREATE TABLE IF NOT EXISTS gold.global_threat_leaderboard (
    threat_name               VARCHAR(500)    NOT NULL,
    threat_hash               CHAR(64),
    threat_category           VARCHAR(50),
    detection_type            VARCHAR(30),
    global_hit_count          BIGINT          DEFAULT 0,
    customers_affected        INTEGER         DEFAULT 0,
    devices_affected          INTEGER         DEFAULT 0,
    countries_affected        SMALLINT        DEFAULT 0,
    max_severity              VARCHAR(10),
    max_severity_score        INTEGER,
    first_seen                TIMESTAMP,
    last_seen                 TIMESTAMP,
    threat_rank               INTEGER,
    days_active               INTEGER         GENERATED ALWAYS AS (DATEDIFF(day, first_seen, last_seen)) STORED,
    gold_processed_at         TIMESTAMP       DEFAULT GETDATE(),
    environment               VARCHAR(10)
)
DISTSTYLE ALL
SORTKEY (threat_rank, global_hit_count)
;

-- ── GOLD: Customer Risk Scores ────────────────────────────
CREATE TABLE IF NOT EXISTS gold.customer_risk_scores (
    customer_id               VARCHAR(50)     NOT NULL,
    event_date                DATE            NOT NULL,
    daily_severity_sum        DECIMAL(10,2),
    daily_events              INTEGER,
    daily_unique_threats      INTEGER,
    rolling_30d_severity      DECIMAL(12,2),
    rolling_30d_events        BIGINT,
    rolling_30d_unique_threats INTEGER,
    risk_score                DECIMAL(12,2),
    risk_tier                 VARCHAR(10),
    gold_processed_at         TIMESTAMP       DEFAULT GETDATE(),
    environment               VARCHAR(10)
)
DISTSTYLE KEY
DISTKEY (customer_id)
COMPOUND SORTKEY (customer_id, event_date)
;

-- ── GOLD: Hourly Detection Trend ──────────────────────────
CREATE TABLE IF NOT EXISTS gold.hourly_detection_trend (
    event_date                DATE            NOT NULL,
    event_hour                SMALLINT        NOT NULL,
    threat_category           VARCHAR(50),
    os_type                   VARCHAR(20),
    country_code              CHAR(2),
    detection_count           INTEGER,
    devices_count             INTEGER,
    avg_severity_score        DECIMAL(5,2),
    high_critical_count       INTEGER,
    gold_processed_at         TIMESTAMP       DEFAULT GETDATE(),
    environment               VARCHAR(10)
)
DISTSTYLE EVEN
SORTKEY (event_date, event_hour)
;

-- ── GOLD: Product Performance KPIs ───────────────────────
CREATE TABLE IF NOT EXISTS gold.product_performance_kpis (
    kpi_date                  DATE            NOT NULL,
    product_version           VARCHAR(20)     NOT NULL,
    os_type                   VARCHAR(20),
    country_code              CHAR(2),
    detection_rate            DECIMAL(7,4),    -- threats detected / total scans
    false_positive_rate       DECIMAL(7,4),
    avg_detection_time_ms     INTEGER,
    active_devices            INTEGER,
    total_scans               BIGINT,
    threats_blocked           BIGINT,
    protection_score          DECIMAL(5,2),   -- composite 0-100
    gold_processed_at         TIMESTAMP       DEFAULT GETDATE()
)
DISTSTYLE KEY
DISTKEY (product_version)
SORTKEY (kpi_date, product_version)
;


-- ── External Tables (Spectrum - S3 Gold Layer) ───────────
CREATE EXTERNAL SCHEMA IF NOT EXISTS spectrum_gold
FROM DATA CATALOG
DATABASE 'mcafee_${environment}_gold'
IAM_ROLE '${redshift_role_arn}'
REGION 'us-east-1'
;

-- ── Materialized Views ────────────────────────────────────

-- Executive Dashboard Summary (refreshed every 2 hours)
CREATE MATERIALIZED VIEW gold.mv_executive_summary
AUTO REFRESH YES
AS
SELECT
    TRUNC(event_date, 'MM')               AS report_month,
    COUNT(DISTINCT customer_id)           AS active_customers,
    SUM(total_events)                     AS total_threats_detected,
    SUM(critical_count + high_count)      AS high_severity_threats,
    SUM(quarantined_count + deleted_count + blocked_count) AS threats_blocked,
    AVG(avg_severity_score)               AS avg_threat_severity,
    COUNT(DISTINCT CASE WHEN risk_tier = 'CRITICAL' THEN r.customer_id END) AS customers_at_critical_risk
FROM gold.daily_threat_summary d
LEFT JOIN gold.customer_risk_scores r USING (customer_id, event_date)
WHERE event_date >= DATEADD(month, -6, CURRENT_DATE)
GROUP BY 1
ORDER BY 1 DESC
;

-- Top 10 Threats This Week
CREATE MATERIALIZED VIEW gold.mv_top_threats_weekly
AUTO REFRESH YES
AS
SELECT
    threat_name,
    threat_category,
    SUM(global_hit_count)   AS weekly_hits,
    MAX(max_severity)       AS peak_severity,
    SUM(customers_affected) AS total_customers,
    threat_rank
FROM gold.global_threat_leaderboard
WHERE last_seen >= DATEADD(day, -7, CURRENT_DATE)
GROUP BY threat_name, threat_category, max_severity, threat_rank
ORDER BY weekly_hits DESC
LIMIT 10
;
