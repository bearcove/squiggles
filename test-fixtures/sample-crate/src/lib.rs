pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn helper_that_panics() {
    inner_panic();
}

fn inner_panic() {
    panic!("something went wrong in inner function");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passing() {
        assert_eq!(add(2, 2), 4);
    }

    #[test]
    fn test_assertion_failure() {
        assert_eq!(add(2, 2), 5, "math is broken");
    }

    #[test]
    fn test_panic_with_message() {
        panic!("intentional panic for testing");
    }

    #[test]
    fn test_panic_in_nested_call() {
        helper_that_panics();
    }

    #[test]
    fn test_unwrap_none() {
        let x: Option<i32> = None;
        x.unwrap();
    }

    #[test]
    fn test_index_out_of_bounds() {
        let v = vec![1, 2, 3];
        let _ = v[10];
    }
}
