/// A module that offers time utilities.
/// In particular, it provides a fake time system,
/// useful for instance when running unit tests and have to
/// deal with timeouts (you don't want to really wait minutes
/// to see something happen).
use std::{
    sync::Mutex,
    time::{Duration, SystemTime, SystemTimeError},
};

/// A context structure that can be shared throughout the application
/// to access the system time (or the fake version of it).
#[derive(Debug)]
pub struct TimeContext {
    /// Mutex storing the mock time.
    /// By default, the mock time feature is disable and the contained
    /// value is None.
    mock_time: Mutex<Option<SystemTime>>,
}

impl TimeContext {
    /// Creates a new context for handling time.
    /// If the input is None, the context will behave as real time.
    /// If the input is Some, the context will work as mock time.
    pub fn new(time: Option<SystemTime>) -> Self {
        Self {
            mock_time: Mutex::new(time),
        }
    }

    /// Returns the elapsed time between two moments.
    /// The behavior depends on whether the mock time is set or not:
    /// 1. If the [`TimeContext::mock_time`] is None, then it returns the real
    ///    elapsed time since the input time until the real current system time
    /// 2. If the [`TimeContext::mock_time`] is Some, then it returns the elapsed
    ///    time until the mock time value
    /// The input time is expected to be in the past, otherwise an error is returned.
    pub fn elapsed(&self, past_time: &SystemTime) -> Result<Duration, SystemTimeError> {
        match *self.mock_time.lock().unwrap() {
            Some(time) => time.duration_since(*past_time),
            None => past_time.elapsed(),
        }
    }

    /// Returns the current time of the application.
    /// The return value depends on how the Time module is used:
    /// 1. if [`TimeContext::mock_time`] is None, then
    ///    the real system time is returned
    /// 2. if [`TimeContext::mock_time`] is Some, than the stored
    ///    mock time is returned
    pub fn now(&self) -> SystemTime {
        match *self.mock_time.lock().unwrap() {
            Some(time) => time,
            None => SystemTime::now(),
        }
    }

    #[cfg(test)]
    /// Sets the mock time to the new value provided.
    /// If this is the first call, it also "enables"
    /// the mock time, meaning that following calls to
    /// [`Self::now()`] will return the mock time and not the
    /// real system one.
    /// This is intended for testing purpose only.
    pub fn set_time(&self, time: SystemTime) {
        *self.mock_time.lock().unwrap() = Some(time);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ops::Add,
        time::{Duration, SystemTime},
    };

    use crate::utils::time::TimeContext;

    /// Check that the TimeContext returns the real system time
    /// when the mock time is not initialized.
    #[test]
    fn test_real_time() {
        let context = TimeContext::new(None);
        let time = context.now();
        let real_time = SystemTime::now();

        // The two times cannot be exactly the same as they were taken in two slightly different moments,
        // but the difference should be very small (below 1 millisecond).
        assert_eq!(real_time.duration_since(time).unwrap().as_millis(), 0);
    }

    /// Check that the mock time works as intended after the first initialization.
    #[test]
    fn test_mock_time() {
        // Set the mock time to "0" (1970-01-01 00:00:00)
        let context = TimeContext::new(Some(SystemTime::UNIX_EPOCH));

        // Check that the stored time is returned
        assert_eq!(context.now(), SystemTime::UNIX_EPOCH);

        // Let's move 10 seconds ahead and check again
        let new_time = SystemTime::UNIX_EPOCH.add(Duration::from_secs(10));
        context.set_time(new_time);
        assert_eq!(context.now(), new_time);
    }

    /// Check that the [`super::elapsed()`] function works as intended when
    /// [`MOCK_TIME`] is not set.
    #[test]
    fn test_real_elapsed_time() {
        let context = TimeContext::new(None);
        let base_time = context.now();

        let mock_duration = context.elapsed(&base_time).unwrap();
        let real_duration = base_time.elapsed().unwrap();

        // The two durations should be different as they are computed in two
        // slightly different moments, but the gap should be minimal (less than 1 ms).
        assert_ne!(mock_duration, real_duration);
        assert!(real_duration - mock_duration < Duration::from_millis(1));
    }

    /// Check that the elapsed time works as intended when using the mock.
    #[test]
    fn test_mock_elapsed_time() {
        // Set the mock time to "0" (1970-01-01 00:00:00)
        let context = TimeContext::new(Some(SystemTime::UNIX_EPOCH));
        let base_time = context.now();

        // If we don't move the time, elapsed must be zero
        assert_eq!(context.elapsed(&base_time).unwrap(), Duration::ZERO);

        let ten_seconds_duration = Duration::from_secs(10);

        // Move the mock time ahead
        context.set_time(base_time.add(ten_seconds_duration));

        // Check the elapsed time value is as expected
        assert_eq!(context.elapsed(&base_time).unwrap(), ten_seconds_duration);
    }
}
