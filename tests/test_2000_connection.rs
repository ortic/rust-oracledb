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
// test_2000_connection()
//-----------------------------------------------------------------------------

mod common;

use common::conn;
use rstest::*;
use std::time::{Duration, Instant};

/// Creates an end user security context for testing.
fn create_end_user_security_context(
    token: String,
    database_access_token: String,
) -> Result<oracledb::EndUserSecurityContext, oracledb::Error> {
    oracledb::EndUserSecurityContext::new(
        oracledb::EndUserIdentity::Token(token),
        database_access_token,
    )
}

/// Tests a single end-to-end attribute matches the reality.
fn test_end_to_end_attr(
    conn: &oracledb::Connection,
    value: &str,
    sql: &str,
) -> Result<(), oracledb::Error> {
    let cursor = conn.query(sql, &[])?;
    for row in cursor {
        let row = row?;
        let fetched_value: Option<String> = row.get(0)?;
        assert_eq!(fetched_value.unwrap_or_default(), value);
    }
    Ok(())
}

#[rstest]
/// test end-to-end attributes
fn test_2000(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    for value in ["oracledb_action", ""] {
        let sql = "select sys_context('userenv', 'action') from dual";
        conn.set_action(value)?;
        test_end_to_end_attr(&conn, value, sql)?;
    }
    for value in ["oracledb_cid", ""] {
        let sql =
            "select sys_context('userenv', 'client_identifier') from dual";
        conn.set_client_identifier(value)?;
        test_end_to_end_attr(&conn, value, sql)?;
    }
    for value in ["oracledb_cinfo", ""] {
        let sql = "select sys_context('userenv', 'client_info') from dual";
        conn.set_client_info(value)?;
        test_end_to_end_attr(&conn, value, sql)?;
    }
    if !common::is_on_oracle_cloud(&conn)? {
        for value in ["oracledb_dbop", ""] {
            let sql = r#"
                select dbop_name
                from v$sql_monitor
                where sid = sys_context('userenv', 'sid')
                  and status = 'EXECUTING'
                "#;
            conn.set_db_op(value)?;
            test_end_to_end_attr(&conn, value, sql)?;
        }
    }
    for value in ["oracledb_module", ""] {
        let sql = "select sys_context('userenv', 'module') from dual";
        conn.set_module(value)?;
        test_end_to_end_attr(&conn, value, sql)?;
    }
    Ok(())
}

#[rstest]
/// test invalid end user security context length
fn test_2001() -> Result<(), oracledb::Error> {
    match create_end_user_security_context(
        "x".repeat(70_000),
        "y".repeat(70_000),
    ) {
        Ok(_) => panic!("expected context creation to fail"),
        Err(err) => {
            assert!(matches!(
                err.kind(),
                oracledb::ErrorKind::InvalidEndUserSecurityContextLength(_)
            ));
        }
    }
    Ok(())
}

#[rstest]
#[case(oracledb::EndUserIdentity::Token("".to_string()))]
#[case(oracledb::EndUserIdentity::DatabaseUser {
    name: "".to_string(),
    key: None,
})]
#[case(oracledb::EndUserIdentity::DatabaseUser {
    name: "".to_string(),
    key: Some("key_2002".to_string()),
})]
#[case(oracledb::EndUserIdentity::DatabaseUser {
    name: "end_user_2002".to_string(),
    key: Some("".to_string()),
})]
/// test end user security context rejects invalid identities
fn test_2002(
    #[case] identity: oracledb::EndUserIdentity,
) -> Result<(), oracledb::Error> {
    match oracledb::EndUserSecurityContext::new(
        identity,
        "database_access_token_2002".to_string(),
    ) {
        Ok(_) => panic!("expected context creation to fail"),
        Err(err) => {
            assert!(matches!(
                err.kind(),
                oracledb::ErrorKind::InvalidEndUserSecurityContext(_)
            ));
        }
    }
    Ok(())
}

#[rstest]
#[case(oracledb::EndUserIdentity::DatabaseUser {
    name: "end_user_2003".to_string(),
    key: Some("key_2003".to_string()),
})]
#[case(oracledb::EndUserIdentity::DatabaseUser {
    name: "end_user_2003".to_string(),
    key: None,
})]
/// test end user security context accepts database user identities
fn test_2003(
    #[case] identity: oracledb::EndUserIdentity,
) -> Result<(), oracledb::Error> {
    oracledb::EndUserSecurityContext::new(
        identity,
        "database_access_token_2003".to_string(),
    )?;
    Ok(())
}

#[rstest]
/// test end user security context rejects empty database access token
fn test_2004() -> Result<(), oracledb::Error> {
    match create_end_user_security_context(
        "end_user_token_2004".to_string(),
        "".to_string(),
    ) {
        Ok(_) => panic!("expected context creation to fail"),
        Err(err) => {
            assert!(matches!(
                err.kind(),
                oracledb::ErrorKind::InvalidEndUserSecurityContext(_)
            ));
        }
    }
    Ok(())
}

#[rstest]
/// Tests missing credentials and missing connect strings before the network
/// layer is used.
fn test_2005() {
    let err = match oracledb::connect(oracledb::Config::default()) {
        Ok(_) => panic!("missing credentials must fail"),
        Err(err) => err,
    };
    assert!(matches!(err.kind(), oracledb::ErrorKind::NoCredentials));

    let err = match oracledb::connect(
        oracledb::Config::default().set_credentials("user", "password"),
    ) {
        Ok(_) => panic!("missing connect string must fail"),
        Err(err) => err,
    };
    assert!(matches!(err.kind(), oracledb::ErrorKind::NoConnectString));
}

#[rstest]
/// Tests that a call timeout is retained across a round trip and can be
/// cleared.
fn test_2006(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let timeout = Duration::from_secs(5);
    conn.set_call_timeout(Some(timeout))?;
    conn.ping()?;
    assert_eq!(conn.call_timeout()?, Some(timeout));

    conn.set_call_timeout(None)?;
    conn.ping()?;
    assert_eq!(conn.call_timeout()?, None);
    Ok(())
}

#[rstest]
/// Tests that explicitly closing a standalone connection rolls back its
/// uncommitted transaction before the session is released.
fn test_2007(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let mut conn = conn;
    let observer = common::conn();
    let _guard =
        common::create_table(&observer, "test_2007", "id number primary key")?;

    conn.execute("insert into test_2007 values (1)", &[])?;
    conn.close()?;

    let row = observer.query_row("select count(*) from test_2007", &[])?;
    let count: i32 = row.get(0)?;
    assert_eq!(count, 0);
    Ok(())
}

#[rstest]
/// Tests that dropping a standalone connection rolls back its uncommitted
/// transaction before its underlying session is closed.
fn test_2008(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let observer = common::conn();
    let _guard =
        common::create_table(&observer, "test_2008", "id number primary key")?;

    conn.execute("insert into test_2008 values (1)", &[])?;
    drop(conn);

    let row = observer.query_row("select count(*) from test_2008", &[])?;
    let count: i32 = row.get(0)?;
    assert_eq!(count, 0);
    Ok(())
}

#[rstest]
/// Verifies a real call timeout interrupts a long operation and leaves the
/// connection reusable after protocol reset.
fn test_2009(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    conn.set_call_timeout(Some(Duration::from_millis(600)))?;
    let started = Instant::now();
    let error = match conn.execute("begin dbms_session.sleep(1); end;", &[]) {
        Ok(_) => {
            panic!("the database call must exceed the configured timeout")
        }
        Err(error) => error,
    };
    let elapsed = started.elapsed();
    assert!(matches!(
        error.kind(),
        oracledb::ErrorKind::CallTimeoutExceeded
    ));
    assert!(elapsed >= Duration::from_millis(200));
    assert!(elapsed < Duration::from_secs(5));

    conn.set_call_timeout(None)?;
    let row = conn.query_row("select 2009 from dual", &[])?;
    assert_eq!(row.get::<i32>(0)?, 2009);
    Ok(())
}

#[test]
/// Tests proxy authentication with a user of the form
/// `proxy_user[session_user]`.
fn test_2010() -> Result<(), oracledb::Error> {
    let test_config = oracledb::get_test_config();
    let admin_conn = oracledb::connect(test_config.admin_config.clone())?;
    let proxy_user = "rsotest_proxy_2010";
    let proxy_password = "Proxy_2010";
    let _ = admin_conn.execute(&format!("drop user {proxy_user}"), &[]);
    admin_conn.execute(
        &format!(
            "create user {proxy_user} identified by \"{proxy_password}\""
        ),
        &[],
    )?;
    admin_conn
        .execute(&format!("grant create session to {proxy_user}"), &[])?;
    admin_conn.execute(
        &format!(
            "alter user {} grant connect through {proxy_user}",
            test_config.user
        ),
        &[],
    )?;
    let result = (|| {
        // The test configuration (with its wallet, if any) as the proxy.
        let config = test_config.config.clone().set_credentials(
            &format!("{proxy_user}[{}]", test_config.user),
            proxy_password,
        );
        let conn = oracledb::connect(config)?;
        let row = conn.query_row(
            "select sys_context('userenv', 'session_user'),
                    sys_context('userenv', 'proxy_user')
             from dual",
            &[],
        )?;
        Ok::<_, oracledb::Error>((
            row.get::<String>(0)?,
            row.get::<String>(1)?,
        ))
    })();
    admin_conn.execute(&format!("drop user {proxy_user}"), &[])?;
    let (session_user, proxy) = result?;
    assert_eq!(session_user, test_config.user.to_uppercase());
    assert_eq!(proxy, proxy_user.to_uppercase());
    Ok(())
}

/// Returns the ORA error number of an error, if it is a database error.
fn ora_code(error: &oracledb::Error) -> Option<usize> {
    match error.kind() {
        oracledb::ErrorKind::DbError(db) => Some(db.code()),
        _ => None,
    }
}

#[rstest]
/// Tests cancelling a running query from another thread: it fails with
/// ORA-01013 and the connection stays usable.
fn test_2011(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let conn = std::sync::Arc::new(conn);
    let worker = conn.clone();
    let started = Instant::now();
    let call = std::thread::spawn(move || {
        worker
            .query_row(
                "select count(*) from all_objects a, all_objects b",
                &[],
            )
            .map(|_| ())
    });
    std::thread::sleep(Duration::from_millis(1000));
    conn.cancel()?;
    let error = call.join().unwrap().expect_err("the query was cancelled");
    assert_eq!(ora_code(&error), Some(1013), "{error}");
    assert!(started.elapsed() < Duration::from_secs(15));
    let row = conn.query_row("select 2011 from dual", &[])?;
    assert_eq!(row.get::<i32>(0)?, 2011);
    Ok(())
}

#[rstest]
/// Tests that cancelling an idle connection does nothing.
fn test_2012(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    conn.cancel()?;
    conn.cancel()?;
    let row = conn.query_row("select 2012 from dual", &[])?;
    assert_eq!(row.get::<i32>(0)?, 2012);
    Ok(())
}

#[rstest]
/// Tests that cancels racing with short calls leave the connection in sync:
/// every call returns its own result or ORA-01013.
fn test_2013(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    let conn = std::sync::Arc::new(conn);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let canceller = {
        let conn = conn.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = conn.cancel();
                n += 1;
                // 1 to 9 ms: some calls finish, some are cancelled, and some
                // cancels come just too late.
                std::thread::sleep(Duration::from_micros(
                    1000 + (n % 9) * 1000,
                ));
            }
        })
    };
    let mut cancelled = 0;
    for i in 0..300i32 {
        // A few milliseconds each, so cancels land in and right after calls.
        match conn.query_row(
            "select count(*) + :1 from dual connect by level <= 20000",
            &[&i],
        ) {
            Ok(row) => assert_eq!(row.get::<i32>(0)?, i + 20000),
            Err(e) if ora_code(&e) == Some(1013) => cancelled += 1,
            Err(e) => panic!("call {i}: {e}"),
        }
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    canceller.join().unwrap();
    for i in 0..5i32 {
        let row = conn.query_row("select :1 * 2 from dual", &[&i])?;
        assert_eq!(row.get::<i32>(0)?, i * 2);
    }
    eprintln!("{cancelled} of 300 calls were cancelled");
    assert!(cancelled > 0 && cancelled < 300, "{cancelled} cancelled");
    Ok(())
}

#[rstest]
/// Tests that a call cancelled by the server (ALTER SYSTEM CANCEL SQL from
/// another session) fails with ORA-01013 and leaves the connection usable.
fn test_2014(conn: oracledb::Connection) -> Result<(), oracledb::Error> {
    if conn.version()?.0 < 18 {
        return Ok(());
    }
    let ids = (conn.session_id()?, conn.serial_num()?);
    let started = Instant::now();
    let call = std::thread::spawn(move || {
        let result = conn
            .query_row(
                "select count(*) from all_objects a, all_objects b",
                &[],
            )
            .map(|_| ());
        (result, conn)
    });
    std::thread::sleep(Duration::from_millis(1000));
    let admin =
        oracledb::connect(oracledb::get_test_config().admin_config.clone())?;
    admin.execute(
        &format!("alter system cancel sql '{}, {}'", ids.0, ids.1),
        &[],
    )?;
    let (result, conn) = call.join().unwrap();
    let error = result.expect_err("the query was cancelled");
    assert_eq!(ora_code(&error), Some(1013), "{error}");
    assert!(started.elapsed() < Duration::from_secs(15));
    let row = conn.query_row("select 2014 from dual", &[])?;
    assert_eq!(row.get::<i32>(0)?, 2014);
    Ok(())
}
