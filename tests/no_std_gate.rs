#![cfg(not(feature = "std"))]

#[test]
fn no_std_compile_smoke() {
    assert_eq!(2 + 2, 4);
}
