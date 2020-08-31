pub(crate) fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

pub(crate) fn concat(ctxt: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ctxt);
    out.extend_from_slice(tag);
    out
}
