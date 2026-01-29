/// Helper that panics with a message
fn helper_that_panics(msg: &str) {
    panic!("{}", msg);
}

/// Another level of indirection
fn intermediate_call(msg: &str) {
    helper_that_panics(msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Install color-backtrace for nicer panic output
    #[ctor::ctor]
    fn init() {
        color_backtrace::install();
    }

    #[test]
    fn test_with_color_backtrace() {
        intermediate_call("this is a test failure with color-backtrace");
    }

    #[test]
    fn test_assertion_failure() {
        let expected = 42;
        let actual = 41;
        assert_eq!(expected, actual, "values should match");
    }

    #[test]
    fn test_simple_panic() {
        panic!("simple panic message");
    }

    #[test]
    fn test_passing() {
        assert!(true);
    }

    #[test]
    fn test_assert_no_message() {
        assert!(false);
    }

    #[test]
    fn test_assert_with_format() {
        let x = 5;
        assert!(x > 10, "x ({}) should be greater than 10", x);
    }

    #[test]
    fn test_assert_ne() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3];
        assert_ne!(a, b, "vectors should be different");
    }

    #[test]
    fn test_unwrap_none() {
        let opt: Option<i32> = None;
        opt.unwrap();
    }

    #[test]
    fn test_unwrap_err() {
        let res: Result<i32, &str> = Err("something went wrong");
        res.unwrap();
    }

    #[test]
    fn test_expect_none() {
        let opt: Option<i32> = None;
        opt.expect("expected a value but got None");
    }

    #[test]
    fn test_index_out_of_bounds() {
        let v = vec![1, 2, 3];
        let _ = v[10];
    }

    #[test]
    fn test_debug_assert() {
        debug_assert!(false, "debug assertion failed");
    }

    #[test]
    fn test_unreachable() {
        unreachable!("this code should not be reached");
    }

    #[test]
    fn test_todo() {
        todo!("implement this later");
    }

    #[test]
    fn test_unimplemented() {
        unimplemented!("not yet done");
    }
}
