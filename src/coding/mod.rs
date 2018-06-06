//! Various coding schemes to be used in conjunction with the core Paillier encryption scheme.

pub mod integral;
use ::BigInteger as BigInt;
use arithimpl::traits::ConvertFrom;

pub fn pack<T>(components: &Vec<T>, component_count: usize, component_size: usize) -> BigInt
where T: Clone, BigInt: From<T>
{
    assert!(components.len() == component_count);
    let mut packed = BigInt::from(components[0].clone());
    for component in &components[1..] {
        packed = packed << component_size;
        packed = packed + BigInt::from(component.clone());
    }
    packed
}

pub fn unpack<T>(mut packed_components: BigInt, component_count: usize, component_size: usize) -> Vec<T>
where T: ConvertFrom<BigInt>
{
    let mask = BigInt::one() << component_size;
    let mut components: Vec<T> = vec![];
    for _ in 0..component_count {
        let raw_component = &packed_components % &mask;  // TODO replace with bitwise AND
        let component = T::_from(&raw_component);
        components.push(component);
        packed_components = &packed_components >> component_size;
    }
    components.reverse();
    components
}
