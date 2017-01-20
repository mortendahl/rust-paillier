
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;
use paillier::arithimpl::traits::*;

// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";
static N: &'static str = "446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562024276317335720389819531817915083642419664574530820516411614402061341540773621609718596217130180876113842466833544592377419546315874157443700724565446359813992789873047692473646165446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562045923774195463";
static P_EXP_Q_MOD_N: &'static str = "167216127033575887543627597836645861047205125657210928573959751482755137615538210337351142826820586625192642801613712405599811895698660256697022034706036302526688254935463675298422321466416268553928456486375399618780536765018283218497477719051444372227826918812735482583824151162705395833327342668518742611088648794167631267226166034273943473474852640344643160320108048818901941885781997670470039501703327746459928325135708813764810716722046027109043738";

fn modpow_right_to_left(base: &BigInteger, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
    let mut base = base.clone();
    let mut exponent = exponent.clone();
    let mut result = BigInteger::one();

    while !BigInteger::is_zero(&exponent) {
        if !BigInteger::is_even(&exponent) {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus;  // waste one of these by having it here but code is simpler (tiny bit)
        exponent = exponent >> 1;
    }
    result
}

pub fn bench_modpow_right_to_left(b: &mut Bencher)
{
    let ref p: BigInteger = str::parse(P).unwrap();
    let ref q: BigInteger = str::parse(Q).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    let ref expected: BigInteger = str::parse(P_EXP_Q_MOD_N).unwrap();
    let ref result = modpow_right_to_left(p, q, n);
    assert_eq!(result, expected);

    b.iter(|| {
        let _ = modpow_right_to_left(p, q, n);
    });
}


fn modpow_right_to_left_noshift(base: &BigInteger, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
    let mut base = base.clone();
    let mut result = BigInteger::one();
    for i in 0..exponent.bit_length() {
        if exponent.bit(i) {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus;  // waste one of these by having it here but code is simpler (tiny bit)
    }
    result
}

pub fn bench_modpow_right_to_left_noshift(b: &mut Bencher) {
    let ref p: BigInteger = str::parse(P).unwrap();
    let ref q: BigInteger = str::parse(Q).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    let ref expected: BigInteger = str::parse(P_EXP_Q_MOD_N).unwrap();
    let ref result = modpow_right_to_left_noshift(p, q, n);
    assert_eq!(result, expected);

    b.iter(|| {
        let _ = modpow_right_to_left_noshift(p, q, n);
    });
}


fn modpow_left_to_right(base: &BigInteger, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
    let bitlen = exponent.bit_length();
    let mut result = base.clone();
    for i in (0..bitlen-1).rev() {
        result = &result * &result % modulus;
        if exponent.bit(i) {
            result = base * result % modulus;
        }
    }
    result
}

pub fn bench_modpow_left_to_right(b: &mut Bencher) {
    let ref p: BigInteger = str::parse(P).unwrap();
    let ref q: BigInteger = str::parse(Q).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    let ref expected: BigInteger = str::parse(P_EXP_Q_MOD_N).unwrap();
    let ref result = modpow_left_to_right(p, q, n);
    assert_eq!(result, expected);

    b.iter(|| {
        let _ = modpow_left_to_right(p, q, n);
    });
}


fn modpow_kary_precompute(base: &BigInteger, modulus: &BigInteger, k: u32) -> Vec<BigInteger> {
    (0..2_usize.pow(k)).map(|i| { base.pow(i) % modulus }).collect()
}

fn modpow_kary(base: &[BigInteger], exponent: &BigInteger, modulus: &BigInteger, k: u32) -> BigInteger {
    let block_length = (exponent.bit_length() + k-1) / k;
    let mut result = BigInteger::one();
    for i in (0..block_length).rev() {

        let mut block_value: usize = 0;
        for j in 0..k {
            if exponent.bit(i * k + j) {
                block_value |= 1 << j;
            }
        }

        for _ in 0..k {
            result = &result * &result % modulus;
        }
        if block_value != 0 {
            result = &base[block_value] * &result % modulus;
        }

    }
    result
}

pub fn bench_modpow_kary(b: &mut Bencher)
{
    let ref p: BigInteger = str::parse(P).unwrap();
    let ref q: BigInteger = str::parse(Q).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    let pe = modpow_kary_precompute(p, n, 7);

    let ref expected: BigInteger = str::parse(P_EXP_Q_MOD_N).unwrap();
    let ref result = modpow_kary(&pe, q, n, 7);
    assert_eq!(result, expected);

    b.iter(|| {
        let _ = modpow_kary(&pe, q, n, 7);
    });
}

pub fn bench_modpow_kary_precompute(b: &mut Bencher)
{
    let ref p: BigInteger = str::parse(P).unwrap();
    let ref q: BigInteger = str::parse(Q).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    b.iter(|| {
        let _ = modpow_kary_precompute(p, n, 5);
    });
}

benchmark_group!(modpow,
    bench_modpow_right_to_left,
    bench_modpow_right_to_left_noshift,
    bench_modpow_left_to_right,
    bench_modpow_kary,
    bench_modpow_kary_precompute
);


// fn gcd_euclidean(mut a: &BigInteger, mut b: &BigInteger) -> BigInteger {
//     let ref mut = 1;
//     while !BigInteger::is_zero(b) {
//         r = a % b;
//         a = b;
//         b = r;
//     }
//     a.clone()
// }

pub fn bench_gcd_euclidean(b: &mut Bencher)
{
    // let ref p: BigInteger = str::parse(P).unwrap();
    // let ref q: BigInteger = str::parse(Q).unwrap();
    //
    // b.iter(|| {
    //     let _ = gcd_euclidean(p, q);
    // });
}

benchmark_group!(gcd,
    bench_gcd_euclidean
);




// 2048 bit modulus
static M: &'static str = "23601375460155562757123678360900229644381030159964965932095920363097284825175029196457022864038449469086188985762066259059164844287276915193108505099612427967057134520230945630209577834878763915645946525724125804370016991193585261991964913084246563304755455418791629494251095184144084978275430600444710605147457044597210354635288909909182640243950968376955162386281524128586829759108414295175173359174297599533960370415928328418610692822180389889327103292184546896322100484378149887147731744901289563127581082141485046742100147976163228583170704180024449958168221243717383276594270459874555884125566472776234343167371";
static A: &'static str = "21018930117366764350898694992115475756052173485791771182687544179958358033442648379881717140743124795619387081396970010890499667136172210312966218568957143129201946866852123295074445358034196665394259630946211193072013608358148621092460056309033055755076990948591152082235051867101135045869471466546045463621376587853840431585298331304787227215313292162326033831873745539574951226687913903557433951322567189013621921213808704150485160383303158594525632194034517900348505951699877787575204939883235676543571052359670010810178870770149864945873121225164484819185495739105096295784137710444211771110429101606275550256350";
static B: &'static str = "1049456643744256352434959721602677127907110199365472601706378014126039959303995626722547931368042305657132646924293851674642443292508841728180500733246045251960133911570297572412453693537030558225338679173630648137463215732376585475109258629619747951700764160276240245814748480929711954296543697662702293607404201507180067226461718268787969529645454496005895521828266259569550435784637440537549153551983871769676237081696240891375685349652543451651292159729862561210127471657215789153992875292166171612269686116623332872858428643868471147737303805064209198596362100835191543083057494447787370833956042849700765709544";


pub fn bench_muldiv_mul(bencer: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();

    bencer.iter(|| {
        let _ = a * b;
    });
}


pub fn bench_muldiv_div(bencer: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();

    bencer.iter(|| {
        let _ = a / b;
    });
}

pub fn bench_muldiv_divmod(bencer: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();

    bencer.iter(|| {
        let _ = a.divmod(b);
    });
}

pub fn bench_muldiv_rem(bencer: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();

    let ref d = b / BigInteger::from(17);

    bencer.iter(|| {
        let _ = a % d;
    });
}

benchmark_group!(muldiv,
    bench_muldiv_mul,
    bench_muldiv_div,
    bench_muldiv_divmod,
    bench_muldiv_rem
);




pub fn bench_mulrem_naive(bencher: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();

    let ref c = a * b;

    bencher.iter(|| {
        // let _ = (a * b) % n;
        let _ = c % n;
    });
}




pub fn bench_mulrem_montgomery(bencher: &mut Bencher)
{
    let ref a: BigInteger = str::parse(A).unwrap();
    let ref b: BigInteger = str::parse(B).unwrap();
    let ref n: BigInteger = str::parse(N).unwrap();
    let ref minusone: BigInteger = str::parse("-1").unwrap();

    let ref c = (a * b) % n;

    let l: usize = 2048 + 64; // n.bit_length() as usize + 1;
    let ref r = BigInteger::one() << l;
    assert!(r > n);
    let ref ahat = (a * r) % n;
    let ref bhat = (b * r) % n;

    let (ref d, ref rinv, ref ninvinv) = BigInteger::egcd(r, n);
    let ref ninv = (ninvinv * (r-1)) % r;
    assert_eq!(d, &BigInteger::one());
    assert_eq!( (r * rinv) % n + n, BigInteger::one() );
    assert_eq!( (n * ninv) % r - r, *minusone );

    let ref s: BigInteger = ahat * bhat;

    bencher.iter(|| {
        let ref m: BigInteger = ((s & (r-1)) * ninv) & (r-1);
        let ref t: BigInteger = (s + m * n) >> l;
        // if t < n {
            // let ref res = (t * rinv) % n;
            // assert_eq!(res, c);
        // } else {
            // let ref res = ((t-n) * rinv) % n + n;
            // assert_eq!(res, c);
        // }

    });
}

benchmark_group!(mulrem,
    bench_mulrem_naive,
    bench_mulrem_montgomery
);



pub fn bench_mont_naive(bencher: &mut Bencher)
{
    let mut a: u64 = 2475173241;
    let mut b: u64 = 3061035151;
    let ref n: u64 = 892583223269281;

    let c = a*b;

    bencher.iter(|| {
        for i in 1..100000 {
            let foo = (c) % n;
            bencher::black_box(foo);
        }
    });
}

pub fn bench_mont_montgomery(bencher: &mut Bencher)
{
    let mut a: u64 = 2475173241;
    let mut b: u64 = 3061035151;
    let n: u64 = 892583223269281;

    let c = (a*b);

    let l: usize = 50;
    let r: u64 = 1 << l;
    assert!(r > n);
    let ahat = (a * r) % n;
    let bhat = (b * r) % n;

    let ninv = 12345678; //(ninvinv * (r-1)) % r;
    // assert_eq!( (r * rinv) % n + n, BigInteger::one() );
    // assert_eq!( (n * ninv) % r - r, *minusone );

    let s = ahat * bhat;

    bencher.iter(|| {
        for i in 1..100000 {
            let m = ((s & (r-1)) * ninv) & (r-1);
            let t = (s + m * n) >> l;
            bencher::black_box(t);
            // if t < n {
            //     let ref res = (t * rinv) % n;
            //     assert_eq!(res, c);
            // } else {
            //     let ref res = ((t-n) * rinv) % n + n;
            //     assert_eq!(res, c);
            // }
        }
    });
}

benchmark_group!(mont,
    bench_mont_naive,
    bench_mont_montgomery
);


benchmark_main!(modpow, gcd, mont, muldiv, mulrem);
// benchmark_main!(mont);
