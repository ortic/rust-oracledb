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
// timestamp.rs
//
// Defines the structure representing Oracle timestamps.
//-----------------------------------------------------------------------------

use chrono::Datelike;
use chrono::Timelike;
use std::fmt;
use std::fmt::Write;

#[cfg(feature = "arrow")]
use arrow_schema::TimeUnit;

use super::tz_regions;
use crate::constants;
use crate::db_type::DbType;
use crate::error::Error;
use crate::read_buffer::FromBuf;
use crate::write_buffer::ToBuf;
use crate::write_buffer::WriteBuffer;

/// Represents the value of DATE, TIMESTAMP, TIMESTAMP WITH LOCAL TIME ZONE and
/// TIMESTAMP WITH TIME ZONE columns in the database.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OracleTimestamp {
    year: i16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanoseconds: u32,
    /// Whether the value has a time zone, as TIMESTAMP WITH TIME ZONE values
    /// do.
    has_time_zone: bool,
    tz_hour_offset: i8,
    tz_minute_offset: i8,
    /// The id of the value's time zone region, 0 for an offset.
    tz_region_id: u16,
}

impl Default for OracleTimestamp {
    fn default() -> Self {
        Self {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            nanoseconds: 0,
            has_time_zone: true,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
            tz_region_id: 0,
        }
    }
}

impl OracleTimestamp {
    #[cfg(feature = "arrow")]
    /// Returns the timestamp in the specified Arrow time unit.
    pub(crate) fn to_timestamp(
        self,
        time_unit: TimeUnit,
    ) -> Result<i64, Error> {
        let timestamp = chrono::NaiveDateTime::try_from(self)?.and_utc();
        match time_unit {
            TimeUnit::Second => Ok(timestamp.timestamp()),
            TimeUnit::Millisecond => Ok(timestamp.timestamp_millis()),
            TimeUnit::Microsecond => Ok(timestamp.timestamp_micros()),
            TimeUnit::Nanosecond => {
                timestamp.timestamp_nanos_opt().ok_or_else(|| {
                    Error::out_of_range("timestamp is outside Arrow range")
                })
            }
        }
    }

    /// Returns the day of the timestamp.
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Returns whether the timestamp has a time zone, as TIMESTAMP WITH TIME
    /// ZONE values do. Without one, the offsets are zero and there's no
    /// region.
    pub fn has_time_zone(&self) -> bool {
        self.has_time_zone
    }

    /// Returns the hour of the timestamp.
    pub fn hour(&self) -> u8 {
        self.hour
    }

    /// Returns whether the timestamp is a UTC timestamp: one with a time zone,
    /// a zero offset and no region.
    pub fn is_utc(&self) -> bool {
        self.has_time_zone
            && self.tz_offset_minutes() == 0
            && self.tz_region().is_none()
    }

    /// Returns the minute of the timestamp.
    pub fn minute(&self) -> u8 {
        self.minute
    }

    /// Returns the month of the timestamp.
    pub fn month(&self) -> u8 {
        self.month
    }

    /// Returns the nanoseconds of the timestamp.
    pub fn nanoseconds(&self) -> u32 {
        self.nanoseconds
    }

    /// Creates a new timestamp given only the date. The time portion is set
    /// to be midnight.
    pub fn new_date(year: i16, month: u8, day: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
            nanoseconds: 0,
            has_time_zone: false,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
            tz_region_id: 0,
        }
    }

    /// Creates a new naive timestamp given the date and time.
    pub fn new_timestamp(
        year: i16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanoseconds: u32,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanoseconds,
            has_time_zone: false,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
            tz_region_id: 0,
        }
    }

    /// Creates a new timestamp given all components, including the time zone
    /// offsets. The date and time are in that time zone. For a negative
    /// offset both offsets are negative (-3 and -30 for -03:30).
    #[allow(clippy::too_many_arguments)]
    pub fn new_timestamp_tz(
        year: i16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanoseconds: u32,
        tz_hour_offset: i8,
        tz_minute_offset: i8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanoseconds,
            has_time_zone: true,
            tz_hour_offset,
            tz_minute_offset,
            tz_region_id: 0,
        }
    }

    /// Creates a new UTC timestamp given the date and time.
    pub fn new_utc_timestamp(
        year: i16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanoseconds: u32,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanoseconds,
            has_time_zone: true,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
            tz_region_id: 0,
        }
    }

    /// Returns the second of the timestamp.
    pub fn second(&self) -> u8 {
        self.second
    }

    /// Returns the time zone hour offset of the timestamp.
    pub fn tz_hour_offset(&self) -> i8 {
        self.tz_hour_offset
    }

    /// Returns the time zone minute offset of the timestamp.
    pub fn tz_minute_offset(&self) -> i8 {
        self.tz_minute_offset
    }

    /// Returns the name of the time zone region of a TIMESTAMP WITH TIME ZONE
    /// value (e.g. `Europe/Zurich`), or None if it has an offset or no time
    /// zone. A region this driver doesn't know (one newer than its table)
    /// comes back in UTC.
    pub fn tz_region(&self) -> Option<&'static str> {
        tz_regions::name(self.tz_region_id)
    }

    /// Returns the year of the timestamp.
    pub fn year(&self) -> i16 {
        self.year
    }

    /// Returns the time zone offset in minutes.
    fn tz_offset_minutes(&self) -> i32 {
        i32::from(self.tz_hour_offset) * 60 + i32::from(self.tz_minute_offset)
    }

    /// Returns the timestamp with its date and time moved by the given number
    /// of minutes, less than a day either way. Oracle's calendar is Julian
    /// before October 15, 1582 and has no year 0, so this doesn't go through
    /// chrono.
    fn add_minutes(mut self, minutes: i32) -> Self {
        let minutes =
            i32::from(self.hour) * 60 + i32::from(self.minute) + minutes;
        let minute_of_day = minutes.rem_euclid(24 * 60);
        self.hour = (minute_of_day / 60) as u8;
        self.minute = (minute_of_day % 60) as u8;
        match minutes.div_euclid(24 * 60) {
            1 => self.next_day(),
            -1 => self.previous_day(),
            _ => {}
        }
        self
    }

    fn next_day(&mut self) {
        if (self.year, self.month, self.day) == (1582, 10, 4) {
            self.day = 15;
        } else if self.day < days_in_month(self.year, self.month) {
            self.day += 1;
        } else if self.month < 12 {
            self.month += 1;
            self.day = 1;
        } else {
            self.year = if self.year == -1 { 1 } else { self.year + 1 };
            self.month = 1;
            self.day = 1;
        }
    }

    fn previous_day(&mut self) {
        if (self.year, self.month, self.day) == (1582, 10, 15) {
            self.day = 4;
        } else if self.day > 1 {
            self.day -= 1;
        } else if self.month > 1 {
            self.month -= 1;
            self.day = days_in_month(self.year, self.month);
        } else {
            self.year = if self.year == 1 { -1 } else { self.year - 1 };
            self.month = 12;
            self.day = 31;
        }
    }
}

/// Returns the number of days in a month of Oracle's calendar.
fn days_in_month(year: i16, month: u8) -> u8 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = if year < 1583 {
                year % 4 == 0
            } else {
                year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
            };
            if leap { 29 } else { 28 }
        }
        _ => 31,
    }
}

impl fmt::Display for OracleTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.nanoseconds
        )?;
        if !self.has_time_zone {
            return Ok(());
        }
        let offset = self.tz_offset_minutes();
        let region = self.tz_region();
        if offset == 0 && region.is_none() {
            return f.write_char('Z');
        }
        // For a negative offset both parts are negative (-3 and -30 for
        // -03:30), as the database sends them.
        let sign = if offset < 0 { '-' } else { '+' };
        write!(
            f,
            "{}{:02}:{:02}",
            sign,
            offset.abs() / 60,
            offset.abs() % 60
        )?;
        // A region follows its offset in brackets, as in RFC 9557.
        if let Some(region) = region {
            write!(f, "[{region}]")?;
        }
        Ok(())
    }
}

impl FromBuf for OracleTimestamp {
    fn from_buf(buf: &[u8]) -> Self {
        let mut nanoseconds: u32 = 0;
        if buf.len() >= constants::ORA_TYPE_SIZE_TIMESTAMP {
            nanoseconds = u32::from_be_bytes(buf[7..11].try_into().unwrap());
        }
        let has_time_zone = buf.len() == constants::ORA_TYPE_SIZE_TIMESTAMP_TZ;
        let mut tz_hour_offset: i8 = 0;
        let mut tz_minute_offset: i8 = 0;
        let mut tz_region_id = 0;
        if has_time_zone {
            if buf[11] & 0x80 != 0 {
                // A region id; its second byte is 0 for some regions.
                tz_region_id =
                    u16::from(buf[11] & 0x7f) << 6 | u16::from(buf[12] >> 2);
            } else if buf[11] != 0 && buf[12] != 0 {
                tz_hour_offset =
                    buf[11].wrapping_sub(constants::TZ_HOUR_OFFSET) as i8;
                tz_minute_offset =
                    buf[12].wrapping_sub(constants::TZ_MINUTE_OFFSET) as i8;
            }
        }
        let value = Self {
            year: ((buf[0] as i16 - 100) * 100 + buf[1] as i16 - 100),
            month: buf[2],
            day: buf[3],
            hour: buf[4] - 1,
            minute: buf[5] - 1,
            second: buf[6] - 1,
            nanoseconds,
            has_time_zone,
            tz_hour_offset,
            tz_minute_offset,
            tz_region_id: 0,
        };
        // A region gets its offset at that (UTC) time; for a negative offset
        // both parts are negative.
        let region_offset =
            tz_regions::name(tz_region_id).and_then(|region| {
                tz_regions::offset_minutes(
                    region,
                    value.year,
                    value.month,
                    value.day,
                    value.hour,
                    value.minute,
                )
            });
        let value = match region_offset {
            Some(offset) => Self {
                tz_hour_offset: (offset / 60) as i8,
                tz_minute_offset: (offset % 60) as i8,
                tz_region_id,
                ..value
            },
            None => value,
        };
        // The date and time of a value with a time zone are sent in UTC, but
        // the fields hold them in the value's own time zone, as
        // new_timestamp_tz() takes them.
        value.add_minutes(value.tz_offset_minutes())
    }
}

impl ToBuf for OracleTimestamp {
    fn to_buf(
        &self,
        buf: &mut WriteBuffer,
        db_type: &'static DbType,
        write_length: bool,
    ) {
        let mut actual_db_type = db_type;
        if db_type == crate::DB_TYPE_TIMESTAMP && self.nanoseconds() == 0 {
            actual_db_type = crate::DB_TYPE_DATE;
        }
        if write_length {
            buf.write_u8(
                actual_db_type.buffer_size_factor.try_into().unwrap(),
            );
        }
        buf.write_u8((self.year() / 100 + 100).try_into().unwrap());
        buf.write_u8((self.year() % 100 + 100).try_into().unwrap());
        buf.write_u8(self.month());
        buf.write_u8(self.day());
        buf.write_u8(self.hour() + 1);
        buf.write_u8(self.minute() + 1);
        buf.write_u8(self.second() + 1);
        if actual_db_type != crate::DB_TYPE_DATE {
            buf.write_u32be(self.nanoseconds());
        }
        if actual_db_type == crate::DB_TYPE_TIMESTAMP_TZ {
            buf.write_u8(constants::TZ_HOUR_OFFSET);
            buf.write_u8(constants::TZ_MINUTE_OFFSET);
        }
    }
}

impl From<chrono::NaiveDateTime> for OracleTimestamp {
    fn from(value: chrono::NaiveDateTime) -> Self {
        Self {
            year: value.year() as i16,
            month: value.month() as u8,
            day: value.day() as u8,
            hour: value.hour() as u8,
            minute: value.minute() as u8,
            second: value.second() as u8,
            nanoseconds: value.nanosecond(),
            has_time_zone: false,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
            tz_region_id: 0,
        }
    }
}

impl TryFrom<OracleTimestamp> for chrono::NaiveDateTime {
    type Error = Error;
    fn try_from(ts: OracleTimestamp) -> Result<Self, Self::Error> {
        chrono::NaiveDate::from_ymd_opt(
            ts.year().into(),
            ts.month().into(),
            ts.day().into(),
        )
        .ok_or_else(|| {
            Error::out_of_range(format!(
                "invalid year-month-day: {}-{}-{}",
                ts.year(),
                ts.month(),
                ts.day()
            ))
        })?
        .and_hms_nano_opt(
            ts.hour().into(),
            ts.minute().into(),
            ts.second().into(),
            ts.nanoseconds(),
        )
        .ok_or_else(|| {
            Error::out_of_range(format!(
                "invalid timestamp: {}-{}-{} {}:{}:{}.{:09}",
                ts.year(),
                ts.month(),
                ts.day(),
                ts.hour(),
                ts.minute(),
                ts.second(),
                ts.nanoseconds()
            ))
        })
    }
}
