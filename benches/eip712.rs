use criterion::{criterion_group, criterion_main, Criterion};
use crypto_signer::evm::messages::Order;
use crypto_signer::{Address, Domain, PermitBuilder, Signature, Signer, TypedMessage};

#[derive(Clone, Copy)]
struct BenchSigner(Address);

impl Signer for BenchSigner {
    type Error = core::convert::Infallible;

    fn address(&self) -> Address {
        self.0
    }

    fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
        let mut r = [0_u8; 32];
        let mut s = [0_u8; 32];
        r.copy_from_slice(&hash);
        for (i, b) in hash.iter().enumerate() {
            s[i] = b.wrapping_add(3);
        }
        Ok(Signature::new(27, r, s))
    }
}

fn domain() -> Domain {
    Domain::new("USDC", "1", 137, Address::new([0x11; 20]))
}

fn bench_permit_sign(c: &mut Criterion) {
    let signer = BenchSigner(Address::new([0x22; 20]));
    c.bench_function("evm_permit_sign", |b| {
        b.iter(|| {
            let unsigned = PermitBuilder::new(domain())
                .spender(Address::new([0x33; 20]))
                .value(1_000_000)
                .nonce(42)
                .deadline(1_700_000_000)
                .build(&signer)
                .expect("builds");
            let _signed = unsigned.sign(&signer).expect("signs");
        });
    });
}

fn bench_order_struct_hash(c: &mut Criterion) {
    let signer = BenchSigner(Address::new([0x44; 20]));
    let order = Order {
        token_id: [0x55; 32],
        price: 72,
        size: 100,
        side: 0,
        nonce: 7,
    };

    c.bench_function("evm_order_sign", |b| {
        b.iter(|| {
            let _signed = TypedMessage::new(domain(), order.clone())
                .sign(&signer)
                .expect("signs");
        });
    });
}

criterion_group!(benches, bench_permit_sign, bench_order_struct_hash);
criterion_main!(benches);
