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
// error_info.rs
//
// Defines the structure representing error information returned by the server.
//-----------------------------------------------------------------------------

use crate::client::Client;
use crate::constants;
use crate::error::Error;
use crate::response::Response;
use crate::rowid::Rowid;

pub(crate) struct ErrorInfo {
    db_error: Option<DbError>,
    cursor_id: u16,
    flags: u8,
    rowcount: u64,
    batch_errors: Vec<DbError>,
}

impl ErrorInfo {
    /// Deserializes the error information from the database response.
    pub fn deserialize(
        resp: &mut Response,
        client: &Client,
    ) -> Result<ErrorInfo, Error> {
        resp.deserialize_status()?;
        let _current_row_num = resp.read_ub4()?;
        let _error_num_short = resp.read_ub2()?;
        let _array_elem_error_1 = resp.read_ub2()?;
        let _array_elem_error_2 = resp.read_ub2()?;
        let cursor_id = resp.read_ub2()?;
        let error_pos = resp.read_ub2()?;
        let _old_sql_type = resp.read_u8()?;
        let _fatal = resp.read_u8()?;
        let _flags_1 = resp.read_u8()?;
        let _user_cursor_options = resp.read_u8()?;
        let _upi_parameter = resp.read_u8()?;
        let flags = resp.read_u8()?;
        let _rowid = Rowid::deserialize(resp)?;
        let _os_error = resp.read_ub4()?;
        let _statement_num = resp.read_u8()?;
        let _call_num = resp.read_u8()?;
        let _padding = resp.read_ub2()?;
        let _success_iters = resp.read_ub4()?;
        if resp.read_ub4()? > 0 {
            let _logical_rowid = resp.read_bytes_with_length()?;
        }
        let batch_errors = Self::deserialize_batch_errors(resp)?;
        let error_num = resp.read_ub4()?;
        let rowcount = resp.read_ub8()?;
        if client.supports_ttc_field_version(constants::TTC_FIELD_VERSION_20_1)
        {
            let _sql_type = resp.read_ub4()?;
            let _server_checksum = resp.read_ub4()?;
        }
        let db_error = if error_num == 0 {
            None
        } else {
            let message = resp.read_utf8_with_length()?;
            Some(DbError {
                code: error_num as usize,
                offset: error_pos as usize,
                message: message.trim_end().to_string(),
            })
        }
        // With batch errors, the rows' errors are in batch_errors instead.
        .filter(|e| e.code != constants::DB_ERR_NUM_ARRAY_DML_ERRORS);

        Ok(ErrorInfo {
            cursor_id,
            flags,
            rowcount,
            db_error,
            batch_errors,
        })
    }

    /// Deserializes the errors of a batch's rows (with batch errors on): an
    /// array of error codes, one of the rows' offsets in the batch and one of
    /// the messages.
    fn deserialize_batch_errors(
        resp: &mut Response,
    ) -> Result<Vec<DbError>, Error> {
        let mut errors = Vec::new();
        let num_errors = resp.read_ub2()?;
        if num_errors > 0 {
            let first_byte = resp.read_u8()?;
            for _ in 0..num_errors {
                if first_byte == constants::TTC_LONG_LENGTH_INDICATOR {
                    resp.read_ub4()?; // chunk length
                }
                errors.push(DbError {
                    code: resp.read_ub2()?.into(),
                    offset: 0,
                    message: String::new(),
                });
            }
            if first_byte == constants::TTC_LONG_LENGTH_INDICATOR {
                resp.advance(1)?; // end marker
            }
        }
        let num_offsets = resp.read_ub4()?;
        if num_offsets > 0 {
            let first_byte = resp.read_u8()?;
            for i in 0..num_offsets as usize {
                if first_byte == constants::TTC_LONG_LENGTH_INDICATOR {
                    resp.read_ub4()?; // chunk length
                }
                let offset = resp.read_ub4()? as usize;
                if let Some(error) = errors.get_mut(i) {
                    error.offset = offset;
                }
            }
            if first_byte == constants::TTC_LONG_LENGTH_INDICATOR {
                resp.advance(1)?; // end marker
            }
        }
        let num_messages = resp.read_ub2()?;
        if num_messages > 0 {
            resp.advance(1)?; // packed size
            for i in 0..num_messages as usize {
                resp.read_ub2()?; // chunk length
                let message =
                    resp.read_utf8_with_length()?.trim_end().to_string();
                if let Some(error) = errors.get_mut(i) {
                    error.message = message;
                }
                resp.advance(2)?; // end marker
            }
        }
        // The database doesn't list them in the rows' order.
        errors.sort_by_key(|e| e.offset);
        Ok(errors)
    }

    /// Returns the cursor id.
    pub(crate) fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Returns whether or not a compilation warning was returned.
    pub(crate) fn is_compilation_warning(&self) -> bool {
        self.flags & 0x20 != 0
    }

    /// Returns the row count.
    pub(crate) fn rowcount(&self) -> u64 {
        self.rowcount
    }

    /// Takes the error message from the response and returns it.
    pub(crate) fn take_db_error(&mut self) -> Option<DbError> {
        self.db_error.take()
    }

    /// Takes the errors of a batch's rows from the response.
    pub(crate) fn take_batch_errors(&mut self) -> Vec<DbError> {
        std::mem::take(&mut self.batch_errors)
    }

    /// Transfers information from another error info structure that was
    /// received earlier. This is intended for us when a batch of statements is
    /// being executed and a single response is being returned.
    pub(crate) fn transfer_into(&mut self, other_info: &mut ErrorInfo) {
        self.rowcount += other_info.rowcount;
    }
}

/// Represents errors returned by the database.
#[derive(Clone, Debug, PartialEq)]
pub struct DbError {
    code: usize,
    offset: usize,
    message: String,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.message)
    }
}

impl DbError {
    /// Returns whether or not a database error should result in the statement
    /// that executed it being closed (and therefore reparsed when another
    /// attempt to execute it takes place). Data integrity errors are known to
    /// be acceptable. All other errors will result in the cursor being closed.
    pub(crate) fn should_close_cursor(&self) -> bool {
        !matches!(
            self.code,
            constants::DB_ERR_NUM_CANNOT_INSERT_NULL
                | constants::DB_ERR_NUM_CHECK_CONSTRAINT_VIOLATED
                | constants::DB_ERR_NUM_CHILD_RECORD_FOUND
                | constants::DB_ERR_NUM_DBOBJECT_CONSTRAINT_VIOLATED
                | constants::DB_ERR_NUM_JSON_SERIALIZER_ERROR
                | constants::DB_ERR_NUM_PARENT_KEY_NOT_FOUND
                | constants::DB_ERR_NUM_VALUE_LARGER_THAN_PRECISION
                | constants::DB_ERR_NUM_UNIQUE_CONSTRAINT_VIOLATED
        )
    }

    /// Returns the error code associated with the database error.
    pub fn code(&self) -> usize {
        self.code
    }

    /// Returns the error message associated with the database error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the offset associated with the database error.
    pub fn offset(&self) -> usize {
        self.offset
    }
}
