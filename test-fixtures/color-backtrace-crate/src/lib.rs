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
}
