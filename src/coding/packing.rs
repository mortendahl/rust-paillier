
use std::ops::{Add, Shl, Shr, Rem};
use num_traits::One;
use arithimpl::traits::ConvertFrom;

pub fn pack<I, T>(components: &Vec<T>, component_count: usize, component_size: usize) -> I
where
    T: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
{
    assert!(components.len() == component_count);
    let mut packed: I = I::from(components[0].clone());
    for component in &components[1..] {
        packed = packed << component_size;
        packed = packed + I::from(component.clone());
    }
    packed
}

pub fn unpack<I, T>(mut packed_components: I, component_count: usize, component_size: usize) -> Vec<T>
where
    T: ConvertFrom<I>,
    I: One,
    I: From<T>,
    I: Shl<usize, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    let mask = I::one() << component_size;
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
