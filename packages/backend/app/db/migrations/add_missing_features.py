"""Add missing feature tables for Panther Dashboard.

This migration adds:
1. alert_correlation_windows - For multi-alert time window tracking
2. compliance_frameworks - Framework definitions
3. compliance_controls - Individual controls
4. compliance_assessments - Assessment history
5. threat_hunts - Hunt definitions
6. hunt_queries - Queries per hunt
7. hunt_results - Execution results
8. webhook_secret and webhook_headers columns to escalation_policies
"""
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, Float,
    ForeignKey, Index, JSON, UUID
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
import uuid


def upgrade(session: Session):
    """Apply migration - create new tables and add columns."""
    from sqlalchemy import text

    # Add webhook columns to escalation_policies
    session.execute(text("""
        ALTER TABLE escalation_policies
        ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255),
        ADD COLUMN IF NOT EXISTS webhook_headers JSONB DEFAULT '{}';
    """))

    # Add saml_settings column to organization_sso for SAML configuration
    session.execute(text("""
        ALTER TABLE organization_sso
        ADD COLUMN IF NOT EXISTS saml_settings JSONB DEFAULT NULL;
    """))

    # Create alert_correlation_windows table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS alert_correlation_windows (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            rule_id UUID NOT NULL,
            window_key VARCHAR(500) NOT NULL,
            alert_count INTEGER DEFAULT 0,
            alert_ids JSONB DEFAULT '[]',
            first_alert_at TIMESTAMP NOT NULL,
            last_alert_at TIMESTAMP NOT NULL,
            triggered BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_correlation_windows_org_rule
            ON alert_correlation_windows(organization_id, rule_id);
        CREATE INDEX IF NOT EXISTS ix_correlation_windows_key
            ON alert_correlation_windows(window_key);
        CREATE INDEX IF NOT EXISTS ix_correlation_windows_last_alert
            ON alert_correlation_windows(last_alert_at);
    """))

    # Create compliance_frameworks table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS compliance_frameworks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            name VARCHAR(255) NOT NULL,
            description TEXT,
            version VARCHAR(50),
            is_active BOOLEAN DEFAULT TRUE,
            total_controls INTEGER DEFAULT 0,
            implemented_controls INTEGER DEFAULT 0,
            coverage_percentage FLOAT DEFAULT 0.0,
            last_assessment_date TIMESTAMP,
            next_assessment_date TIMESTAMP,
            created_by VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_compliance_frameworks_org
            ON compliance_frameworks(organization_id);
        CREATE INDEX IF NOT EXISTS ix_compliance_frameworks_name
            ON compliance_frameworks(organization_id, name);
    """))

    # Create compliance_controls table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS compliance_controls (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
            control_id VARCHAR(50) NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT,
            status VARCHAR(50) DEFAULT 'not_implemented',
            evidence TEXT,
            evidence_links JSONB DEFAULT '[]',
            owner VARCHAR(255),
            due_date TIMESTAMP,
            last_reviewed_at TIMESTAMP,
            reviewed_by VARCHAR(255),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_compliance_controls_framework
            ON compliance_controls(framework_id);
        CREATE INDEX IF NOT EXISTS ix_compliance_controls_status
            ON compliance_controls(framework_id, status);
        CREATE UNIQUE INDEX IF NOT EXISTS ix_compliance_controls_unique
            ON compliance_controls(framework_id, control_id);
    """))

    # Create compliance_assessments table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS compliance_assessments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
            assessment_date TIMESTAMP NOT NULL,
            coverage_score FLOAT DEFAULT 0.0,
            total_controls INTEGER DEFAULT 0,
            implemented_count INTEGER DEFAULT 0,
            partial_count INTEGER DEFAULT 0,
            not_implemented_count INTEGER DEFAULT 0,
            notes TEXT,
            assessor VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_compliance_assessments_framework
            ON compliance_assessments(framework_id);
        CREATE INDEX IF NOT EXISTS ix_compliance_assessments_date
            ON compliance_assessments(framework_id, assessment_date DESC);
    """))

    # Create threat_hunts table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS threat_hunts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            title VARCHAR(500) NOT NULL,
            hypothesis TEXT NOT NULL,
            description TEXT,
            mitre_techniques JSONB DEFAULT '[]',
            data_sources JSONB DEFAULT '[]',
            status VARCHAR(50) DEFAULT 'draft',
            priority VARCHAR(20) DEFAULT 'medium',
            findings_count INTEGER DEFAULT 0,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            created_by VARCHAR(255) NOT NULL,
            assigned_to VARCHAR(255),
            tags JSONB DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_threat_hunts_org
            ON threat_hunts(organization_id);
        CREATE INDEX IF NOT EXISTS ix_threat_hunts_status
            ON threat_hunts(organization_id, status);
        CREATE INDEX IF NOT EXISTS ix_threat_hunts_created_by
            ON threat_hunts(organization_id, created_by);
    """))

    # Create hunt_queries table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS hunt_queries (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            hunt_id UUID NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            sql_query TEXT NOT NULL,
            query_type VARCHAR(50) DEFAULT 'detection',
            expected_results TEXT,
            order_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_hunt_queries_hunt
            ON hunt_queries(hunt_id);
    """))

    # Create hunt_results table
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS hunt_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            hunt_id UUID NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
            query_id UUID REFERENCES hunt_queries(id) ON DELETE SET NULL,
            status VARCHAR(50) DEFAULT 'pending',
            results_count INTEGER DEFAULT 0,
            findings JSONB DEFAULT '[]',
            raw_results JSONB,
            execution_time_ms INTEGER,
            error_message TEXT,
            executed_at TIMESTAMP,
            executed_by VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_hunt_results_hunt
            ON hunt_results(hunt_id);
        CREATE INDEX IF NOT EXISTS ix_hunt_results_query
            ON hunt_results(query_id);
        CREATE INDEX IF NOT EXISTS ix_hunt_results_status
            ON hunt_results(hunt_id, status);
    """))

    session.commit()
    print("Migration completed: add_missing_features")


def downgrade(session: Session):
    """Revert migration - drop tables and columns."""
    from sqlalchemy import text

    # Drop tables in reverse order (respecting foreign keys)
    session.execute(text("""
        DROP TABLE IF EXISTS hunt_results CASCADE;
        DROP TABLE IF EXISTS hunt_queries CASCADE;
        DROP TABLE IF EXISTS threat_hunts CASCADE;
        DROP TABLE IF EXISTS compliance_assessments CASCADE;
        DROP TABLE IF EXISTS compliance_controls CASCADE;
        DROP TABLE IF EXISTS compliance_frameworks CASCADE;
        DROP TABLE IF EXISTS alert_correlation_windows CASCADE;
    """))

    # Remove webhook columns from escalation_policies
    session.execute(text("""
        ALTER TABLE escalation_policies
        DROP COLUMN IF EXISTS webhook_secret,
        DROP COLUMN IF EXISTS webhook_headers;
    """))

    # Remove saml_settings column from organization_sso
    session.execute(text("""
        ALTER TABLE organization_sso
        DROP COLUMN IF EXISTS saml_settings;
    """))

    session.commit()
    print("Migration reverted: add_missing_features")
