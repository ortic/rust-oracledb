//-----------------------------------------------------------------------------
// Copyright (c) 2026, Oracle and/or its affiliates.
//
// This software is dual-licensed to you under the Universal Permissive License
// (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl and Apache License
// 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose
// either license.
//
// If you elect to accept the software under the Apache License, Version 2.0,
// the following applies:
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// test_1100_timestamps()
//-----------------------------------------------------------------------------

mod common;

use common::conn;
use rstest::*;

#[rstest]
/// test binding and fetching OracleTimestamp
fn test_1200(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let new_date = oracledb::OracleTimestamp::new_date;
    let new_timestamp = oracledb::OracleTimestamp::new_timestamp;
    let options = vec![
        new_date(2025, 11, 21),
        new_timestamp(1987, 6, 15, 14, 38, 25, 123456789),
    ];
    for value in options {
        let cursor = conn.query("select :1 from dual", &[&value])?;
        for row in cursor {
            let row = row?;
            let fetched_value: oracledb::OracleTimestamp = row.get(0)?;
            assert_eq!(fetched_value, value);
        }
    }
    Ok(())
}

#[rstest]
/// test query with DATE
fn test_1201(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let cursor = conn.query(
        r#"
            select to_date('2025-10-31 09:46:25', 'YYYY-MM-DD HH24:MI:SS')
            from dual
        "#,
        &[],
    )?;
    for row in cursor {
        let row = row?;
        let value: oracledb::OracleTimestamp = row.get(0)?;
        assert_eq!(value.to_string(), "2025-10-31T09:46:25.000000000Z");
    }
    Ok(())
}

#[rstest]
/// test query with TIMESTAMP
fn test_1202(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let cursor = conn.query(
        r#"
            select to_timestamp('2025-10-31 11:39:58.123456789',
                'YYYY-MM-DD HH24:MI:SS.FF9')
            from dual
        "#,
        &[],
    )?;
    for row in cursor {
        let row = row?;
        let value: oracledb::OracleTimestamp = row.get(0)?;
        assert_eq!(value.to_string(), "2025-10-31T11:39:58.123456789Z");
    }
    Ok(())
}

#[rstest]
/// test query with TIMESTAMP WITH LOCAL TIME ZONE
fn test_1203(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let cursor = conn.query(
        r#"
            select cast(to_timestamp('2025-10-31 11:46:01.987654',
                'YYYY-MM-DD HH24:MI:SS.FF6') as timestamp with local time zone)
            from dual
        "#,
        &[],
    )?;
    for row in cursor {
        let row = row?;
        let value: oracledb::OracleTimestamp = row.get(0)?;
        assert_eq!(value.to_string(), "2025-10-31T11:46:01.987654000Z");
    }
    Ok(())
}

#[rstest]
/// test query with TIMESTAMP WITH TIME ZONE
fn test_1204(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let cursor = conn.query(
        r#"
            select cast(to_timestamp_tz('2025-10-31 11:52:15.456 -06:00',
                'YYYY-MM-DD HH24:MI:SS.FF3 TZH:TZM')
                as timestamp with time zone)
            from dual
        "#,
        &[],
    )?;
    for row in cursor {
        let row = row?;
        let value: oracledb::OracleTimestamp = row.get(0)?;
        assert_eq!(value.to_string(), "2025-10-31T11:52:15.456000000-06:00");
    }
    Ok(())
}

#[rstest]
/// test fetching null values for DATE/TIMESTAMP/TIMESTAMP TZ/TIMESTAMP LTZ
fn test_1205(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let cursor = conn.query(
        r#"
        select
            cast(null as date),
            cast(null as timestamp),
            cast(null as timestamp with local time zone),
            cast(null as timestamp with time zone)
        from dual
        "#,
        &[],
    )?;
    for row in cursor {
        let row = row?;
        let v1: Option<oracledb::OracleTimestamp> = row.get(0)?;
        let v2: Option<oracledb::OracleTimestamp> = row.get(1)?;
        let v3: Option<oracledb::OracleTimestamp> = row.get(2)?;
        let v4: Option<oracledb::OracleTimestamp> = row.get(3)?;
        assert!(v1.is_none());
        assert!(v2.is_none());
        assert!(v3.is_none());
        assert!(v4.is_none());
    }
    Ok(())
}

#[rstest]
/// test timestamp fractional second boundaries
fn test_1206(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let row = conn.query_row(
        r#"
        select
            timestamp '2026-01-01 00:00:00.000000001',
            timestamp '2026-12-31 23:59:59.999999999'
        from dual
        "#,
        &[],
    )?;
    let low: oracledb::OracleTimestamp = row.get(0)?;
    let high: oracledb::OracleTimestamp = row.get(1)?;
    assert_eq!(low.nanoseconds(), 1);
    assert_eq!(high.nanoseconds(), 999_999_999);
    assert_eq!(high.second(), 59);
    Ok(())
}

#[rstest]
/// test supported DATE lower and upper year boundaries
fn test_1207(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let row = conn.query_row(
        r#"
        select
            date '0001-01-01',
            date '9999-12-31'
        from dual
        "#,
        &[],
    )?;
    let low: oracledb::OracleTimestamp = row.get(0)?;
    let high: oracledb::OracleTimestamp = row.get(1)?;
    assert_eq!(low.to_string(), "0001-01-01T00:00:00.000000000Z");
    assert_eq!(high.to_string(), "9999-12-31T00:00:00.000000000Z");
    Ok(())
}

#[rstest]
/// test invalid DATE values return database errors
fn test_1208(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    for value in ["0000-01-01", "10000-01-01"] {
        let sql = format!("select to_date('{value}', 'YYYY-MM-DD') from dual");
        let err = match conn.query(&sql, &[]) {
            Ok(_) => panic!("expected invalid DATE value to fail: {value}"),
            Err(err) => err,
        };
        assert!(matches!(err.kind(), oracledb::ErrorKind::DbError(_)));
    }
    Ok(())
}

#[test]
/// Verifies timestamp components and fixed-offset display behavior without a
/// database connection.
fn test_1209() {
    let timestamp = oracledb::OracleTimestamp::new_timestamp_tz(
        2026,
        9,
        3,
        14,
        5,
        6,
        123_456_789,
        5,
        30,
    );
    assert_eq!(timestamp.year(), 2026);
    assert_eq!(timestamp.month(), 9);
    assert_eq!(timestamp.day(), 3);
    assert_eq!(timestamp.hour(), 14);
    assert_eq!(timestamp.minute(), 5);
    assert_eq!(timestamp.second(), 6);
    assert_eq!(timestamp.nanoseconds(), 123_456_789);
    assert_eq!(timestamp.tz_hour_offset(), 5);
    assert_eq!(timestamp.tz_minute_offset(), 30);
    assert_eq!(timestamp.to_string(), "2026-09-03T14:05:06.123456789+05:30");
}

#[rstest]
/// test that TIMESTAMP WITH TIME ZONE values are in their own time zone, also
/// when that is another day than in UTC
fn test_1210(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    for value in [
        "2026-10-22 13:05:06 +02:00",
        // UTC is the day before, or the day after.
        "2026-01-01 01:30:00 +05:30",
        "2025-12-31 22:00:00 -03:30",
        "2026-03-01 00:15:00 -00:30",
        "2024-03-01 00:30:00 +14:00",
        // Julian calendar, the switch to the Gregorian one, no year 0.
        "1500-03-01 00:30:00 +01:00",
        "1582-10-15 00:30:00 +01:00",
        "1582-10-04 23:30:00 -01:00",
        "0001-01-01 00:30:00 +01:00",
    ] {
        let row = conn.query_row(
            r#"
            select
                ts,
                to_number(to_char(ts, 'SYYYY')),
                to_number(to_char(ts, 'MM')),
                to_number(to_char(ts, 'DD')),
                to_number(to_char(ts, 'HH24')),
                to_number(to_char(ts, 'MI')),
                to_number(to_char(ts, 'SS')),
                extract(timezone_hour from ts) * 60
                    + extract(timezone_minute from ts)
            from (
                select to_timestamp_tz(:1, 'YYYY-MM-DD HH24:MI:SS TZH:TZM') ts
                from dual
            )
            "#,
            &[&value],
        )?;
        let ts: oracledb::OracleTimestamp = row.get(0)?;
        let fetched = (
            i32::from(ts.year()),
            i32::from(ts.month()),
            i32::from(ts.day()),
            i32::from(ts.hour()),
            i32::from(ts.minute()),
            i32::from(ts.second()),
            i32::from(ts.tz_hour_offset()) * 60
                + i32::from(ts.tz_minute_offset()),
        );
        let expected = (
            row.get::<i32>(1)?,
            row.get::<i32>(2)?,
            row.get::<i32>(3)?,
            row.get::<i32>(4)?,
            row.get::<i32>(5)?,
            row.get::<i32>(6)?,
            row.get::<i32>(7)?,
        );
        assert_eq!(fetched, expected, "{value}");
    }
    let row = conn.query_row(
        "select timestamp '2026-10-22 13:05:06 +02:00' from dual",
        &[],
    )?;
    let ts: oracledb::OracleTimestamp = row.get(0)?;
    assert_eq!(
        ts,
        oracledb::OracleTimestamp::new_timestamp_tz(
            2026, 10, 22, 13, 5, 6, 0, 2, 0
        )
    );
    Ok(())
}

#[test]
/// Verifies the display of negative time zone offsets.
fn test_1211() {
    let new_timestamp_tz = oracledb::OracleTimestamp::new_timestamp_tz;
    assert_eq!(
        new_timestamp_tz(2026, 3, 1, 0, 15, 0, 0, -3, -30).to_string(),
        "2026-03-01T00:15:00.000000000-03:30"
    );
    assert_eq!(
        new_timestamp_tz(2026, 3, 1, 0, 15, 0, 0, 0, -30).to_string(),
        "2026-03-01T00:15:00.000000000-00:30"
    );
    assert_eq!(
        new_timestamp_tz(2026, 3, 1, 0, 15, 0, 0, -6, 0).to_string(),
        "2026-03-01T00:15:00.000000000-06:00"
    );
}

#[rstest]
/// test that TIMESTAMP WITH TIME ZONE values with a time zone region come back
/// with that region, at the right instant, for every region the database
/// knows; and in its current offset, which the driver takes from the IANA
/// rules of chrono-tz rather than the server's time zone file
fn test_1212(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    // Rules changed after time zone file 43 (Paraguay keeps -03 since 2024).
    const NEWER_RULES: [&str; 1] = ["America/Asuncion"];
    let rows = conn.query(
        r#"
        select
            ts,
            extract(timezone_region from ts),
            extract(timezone_hour from ts) * 60
                + extract(timezone_minute from ts),
            to_char(sys_extract_utc(ts), 'YYYY-MM-DD HH24:MI:SS')
        from (
            select from_tz(d.local_time, r.tzname) ts
            from (select distinct tzname from v$timezone_names) r,
                (
                    select timestamp '2026-07-01 12:00:00' local_time
                    from dual
                    union all
                    select timestamp '2026-01-15 12:00:00' from dual
                    union all
                    select timestamp '1950-07-15 12:00:00' from dual
                    union all
                    select timestamp '1880-01-01 12:00:00' from dual
                ) d
        )
        "#,
        &[],
    )?;
    let mut count = 0;
    let mut mismatches = Vec::new();
    for row in rows {
        let row = row?;
        let ts: oracledb::OracleTimestamp = row.get(0)?;
        let region: String = row.get(1)?;
        let offset = i32::from(ts.tz_hour_offset()) * 60
            + i32::from(ts.tz_minute_offset());
        let utc = chrono::NaiveDateTime::try_from(ts)?
            - chrono::Duration::minutes(offset.into());
        let expected_utc = chrono::NaiveDateTime::parse_from_str(
            &row.get::<String>(3)?,
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap();
        let current = ts.year() == 2026;
        if ts.tz_region() != Some(region.as_str())
            || utc != expected_utc
            || (current
                && offset != row.get::<i32>(2)?
                && !NEWER_RULES.contains(&region.as_str()))
        {
            mismatches.push(format!("{region}: {ts} (UTC {expected_utc})"));
        }
        count += 1;
    }
    assert!(count > 2000, "{count}");
    assert!(
        mismatches.is_empty(),
        "{} of {count}:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    Ok(())
}

#[rstest]
/// Verifies the display of values with a time zone region and with an offset.
fn test_1213(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let row = conn.query_row(
        r#"
        select
            from_tz(timestamp '2026-07-01 12:00:00', 'Europe/Zurich'),
            from_tz(timestamp '2026-01-15 12:00:00', 'UTC'),
            from_tz(timestamp '2026-07-01 12:00:00', '+02:00')
        from dual
        "#,
        &[],
    )?;
    let display = |i| -> Result<String, oracledb::Error> {
        Ok(row.get::<oracledb::OracleTimestamp>(i)?.to_string())
    };
    assert_eq!(
        display(0)?,
        "2026-07-01T12:00:00.000000000+02:00[Europe/Zurich]"
    );
    assert_eq!(display(1)?, "2026-01-15T12:00:00.000000000+00:00[UTC]");
    assert_eq!(display(2)?, "2026-07-01T12:00:00.000000000+02:00");
    Ok(())
}
