use core::panic;
use paste::paste;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem::{self, Discriminant};
use std::ops::{AddAssign, MulAssign, Neg};

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::Deserialize;

use error::{Error, Result};

use crate::error;

/// Starting point: https://serde.rs/impl-deserializer.html
///
/// Selector/enums:
///
/// Needed to select enum variant (the selector is always the first field except
/// for in Command, Response and in TPMS_ATTEST). The selector is always a u16
/// or u32.
///
/// If a struct with a enum member has more than two members (selector, enum),
/// all other members will have to be combined into a common enum member.
///
/// Size:
///
/// Needed as size for dynamically-sized arrays. The size is always before the
/// array. Size is always u8, u16 or u32. Note: there are statically-sized
/// arrays which are enum variants.
pub struct Deserializer<'de> {
    // input data, and bytes are truncated off the beginning as data is parsed
    input: &'de [u8],
    level: usize,
    // only used for logging
    field_names: HashMap<usize, &'static [&'static str]>,
    // Value of first field in struct. Needed to select enum variant (the
    // selector is always the first field except for in Command, Response and
    // in TPMS_ATTEST). The selector is always a u16 or u32.
    first_field: HashMap<usize, u32>,
    // Value of previous field in struct. Needed as size for dynamically-sized
    // arrays. The size is always before the array. Size is always u8, u16 or
    // u32.
    // Note: there are statically-sized arrays which are enum variants.
    previous_field: HashMap<usize, u32>,
}

impl Deserializer<'_> {
    pub fn level_push(&mut self) {
        self.level += 1;
    }

    pub fn level_pop(&mut self) {
        if self.level == 0 {
            panic!("Cannot pop non-existant indent. This is a bug.");
        }

        self.level -= 1;
    }

    pub fn indent(&self) -> usize {
        const INDENT_SPACES: usize = 4;
        self.level * INDENT_SPACES
    }

    pub fn get_field_names(&mut self) -> &'static [&'static str] {
        self.field_names
            .get(&self.level)
            .expect("Cannot get fields for this level.")
    }

    pub fn get_field_names_previous(&mut self) -> &'static [&'static str] {
        self.field_names
            .get(&(self.level - 1))
            .expect("Cannot get fields for this level.")
    }

    pub fn set_field_names(&mut self, fields: &'static [&'static str]) {
        self.field_names.insert(self.level, fields);
    }

    pub fn get_first_field(&mut self) -> u32 {
        *self
            .first_field
            .get(&self.level)
            .expect("Cannot get first_field for this level.")
    }

    pub fn set_first_field(&mut self, field: u32) {
        self.first_field.insert(self.level, field);
    }

    pub fn get_previous_field(&mut self) -> u32 {
        *self
            .previous_field
            .get(&self.level)
            .expect("Cannot get previous_field for this level.")
    }

    pub fn set_previous_field(&mut self, field: u32) {
        self.previous_field.insert(self.level, field);
    }
}

impl<'de> Deserializer<'de> {
    pub fn from_bytes(input: &'de [u8]) -> Self {
        Deserializer {
            input,
            level: 0,
            field_names: HashMap::new(),
            first_field: HashMap::new(),
            previous_field: HashMap::new(),
        }
    }
}

pub fn from_bytes<'a, T>(s: &'a [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_bytes(s);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::TrailingCharacters)
    }
}

macro_rules! define_parse {
    ($T:ty) => {
        paste! {
            /// Parse $T (u8, u16, ..., i8, i16, ...) from big-endian
            fn [<parse_ $T>] (&mut self) -> Result<$T> {
                let len = mem::size_of::<$T>();
                let buffer = self.input[..len].try_into().map_err(|_| Error::Eof)?;
                self.input = &self.input[len..];
                Ok($T::from_be_bytes(buffer))
            }
        }
    };
}

impl<'de> Deserializer<'de> {
    /// Look at the first byte in the input without consuming it.
    fn peek_byte(&mut self) -> Result<u8> {
        self.input.get(0).copied().ok_or(Error::Eof)
    }

    /// Consume the first byte in the input.
    fn next_byte(&mut self) -> Result<u8> {
        let byte = self.peek_byte()?;
        self.input = &self.input[1..];
        Ok(byte)
    }

    define_parse!(u8);
    define_parse!(u16);
    define_parse!(u32);
    define_parse!(u64);
    define_parse!(i8);
    define_parse!(i16);
    define_parse!(i32);
    define_parse!(i64);

    /// Parse byte, 0 is false, everything else is true.
    fn parse_bool(&mut self) -> Result<bool> {
        let bool = self.parse_u8()? != 0;
        Ok(bool)
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    /// This protocol is not self-describing: unimplemented
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_bool()?;
        log::info!("deserializing {:i$} :bool = {}", "", v, i = self.indent());
        visitor.visit_bool(v)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_i8()?;
        log::info!("deserializing {:i$} :i8 = {:02x}", "", v, i = self.indent());
        visitor.visit_i8(v)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_i16()?;
        log::info!(
            "deserializing {:i$} :i16 = {:04x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_i16(v)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_i32()?;
        log::info!(
            "deserializing {:i$} :i32 = {:08x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_i32(v)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_i64()?;
        log::info!(
            "deserializing {:i$} :i64 = {:016x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_i64(v)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_u8()?;
        log::info!("deserializing {:i$} :u8 = {:02x}", "", v, i = self.indent());
        visitor.visit_u8(v)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_u16()?;
        log::info!(
            "deserializing {:i$} :u16 = {:04x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_u16(v)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_u32()?;
        log::info!(
            "deserializing {:i$} :u32 = {:08x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_u32(v)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = self.parse_u64()?;
        log::info!(
            "deserializing {:i$} :u64 = {:016x}",
            "",
            v,
            i = self.indent()
        );
        visitor.visit_u64(v)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // TODO check if size was 0 or selector selected unit variant?
        // if self.input.starts_with("null") {
        //     self.input = &self.input["null".len()..];
        //     visitor.visit_none()
        // } else {
        // visitor.visit_some(self)
        // }
        unimplemented!()
    }

    // In Serde, unit means an anonymous value containing no data.
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // Unit struct means a named value containing no data.
    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    // Called on arrays. We parse an extra u16 before to get the number of elements.
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.level_push();
        let size = self.parse_u16()? as usize; // TODO what if another type? Maybe via Associated types
        log::info!(
            "deserializing {:i$}dynamic array size (u16): {}",
            "",
            size,
            i = self.indent()
        );
        let value = visitor.visit_seq(DynamicalArrayAccess::new(self, size))?;
        self.level_pop();
        Ok(value)
    }

    // Called by deserialize_struct()
    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let value = visitor.visit_seq(StructAccess::new(self, len))?;
        Ok(value)
    }

    // Tuple structs look just like sequences in JSON.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!("deserializing {:i$}map", "", i = self.indent());
        let value = visitor.visit_map(EnumMapAccess::new(self, 0))?;
        Ok(value)
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!("deserializing {:i$}struct {}", "", name, i = self.indent());
        // TODO logging field names: deserialize_tuple does not know field
        // names, so we need to add HashMap<level, fields>
        self.level_push();
        self.set_field_names(fields);
        let value = self.deserialize_tuple(fields.len(), visitor);
        self.level_pop();

        value
    }

    // Part of a struct. Selector (i.e. discriminant) is always first member of
    // the struct (except in TPMS_ATTEST where it is comes after magic:
    // TPM_GENERATED). Selector is always TPMI/TPM_ALG/u16 (except in
    // TPMS_CAPABILITY_DATA where it is TPM_CAP/u32)
    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!("deserializing {:i$}enum {}", "", name, i = self.indent());
        // TODO logging field names: deserialize_tuple does not know field
        // names, so we need to add HashMap<level, fields>

        self.level_push();
        self.set_field_names(variants);
        let value = visitor.visit_enum(MyEnumAccess::new(self))?;
        self.level_pop();

        Ok(value)
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!(
            "deserializing {:i$}deserialize_identifier",
            "",
            i = self.indent()
        );
        unimplemented!()
    }

    // Like `deserialize_any`
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

struct StructAccess<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    idx: usize,
}

impl<'a, 'de> StructAccess<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>, len: usize) -> Self {
        StructAccess { de, idx: 0 }
    }
}

impl<'de, 'a> SeqAccess<'de> for StructAccess<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        log::info!(
            "deserializing {:i$}.{}",
            "",
            self.de.get_field_names()[self.idx],
            i = self.de.indent()
        );

        // TODO assuming this is a struct
        let value = DeserializeSeed::deserialize(seed, &mut *self.de)?;
        if self.idx == 0 {
            self.de.set_first_field(42); // TODO
        }
        self.de.set_previous_field(42); // TODO
        self.idx += 1;
        Ok(Some(value))
    }
}

struct DynamicalArrayAccess<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    idx: usize,
    len: usize,
}

impl<'a, 'de> DynamicalArrayAccess<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>, len: usize) -> Self {
        DynamicalArrayAccess { de, len, idx: 0 }
    }
}

impl<'de, 'a> SeqAccess<'de> for DynamicalArrayAccess<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        if !(self.idx < self.len) {
            return Ok(None);
        }

        log::info!(
            "deserializing {:i$}element[{}]",
            "",
            self.idx,
            i = self.de.indent()
        );

        // TODO assuming this is a struct
        let value = DeserializeSeed::deserialize(seed, &mut *self.de)?;
        // if self.idx == 0 {
        //     self.de.set_first_field(42); // TODO
        // }
        // self.de.set_previous_field(42); // TODO
        self.idx += 1;
        Ok(Some(value))
    }
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for DynamicalArrayAccess<'a, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        log::info!(
            "---------deserializing {:i$}next_key_seed",
            "",
            i = self.de.indent()
        );
        //seed.deserialize(&mut *self.de).map(Some)
        Ok(None)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        log::info!(
            "---------------deserializing {:i$}next_value_seed",
            "",
            i = self.de.indent()
        );
        unimplemented!()
    }
}

struct EnumMapAccess<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
}

impl<'a, 'de> EnumMapAccess<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>, len: usize) -> Self {
        EnumMapAccess { de }
    }
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for EnumMapAccess<'a, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        log::info!("deserializing {:i$}next_key_seed", "", i = self.de.indent());
        //seed.deserialize(&mut *self.de).map(Some)
        //Ok(None)
        let v = DeserializeSeed::deserialize(seed, &mut *self.de)?;
        Ok(Some(v))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        log::info!(
            "deserializing {:i$}next_value_seed",
            "",
            i = self.de.indent()
        );
        DeserializeSeed::deserialize(seed, &mut *self.de)
    }
}

struct MyEnumAccess<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
}

impl<'a, 'de> MyEnumAccess<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>) -> Self {
        MyEnumAccess { de }
    }
}

// `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// which variant of the enum is supposed to be deserialized.
//
// Note that all enum deserialization methods in Serde refer exclusively to the
// "externally tagged" enum representation.
impl<'de, 'a> EnumAccess<'de> for MyEnumAccess<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    /// `variant` is called to identify which variant to deserialize.
    ///
    /// `Deserialize` implementations should typically use `EnumAccess::variant`
    /// instead.
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        log::info!(
            "deserializing {:i$}EnumAccess.variant_seed",
            "",
            i = self.de.indent()
        );

        //let value = DeserializeSeed::deserialize(seed, &mut *self.de)?;
        //let value = seed.deserialize(&mut *self.de)?);

        //let variant: u16 = 35;
        let mut variant = self.de.parse_u16()?; // TODO what if selector is no u16
        log::info!(
            "deserializing {:i$} :u16 = {:04x}",
            "",
            variant,
            i = self.de.indent()
        );
        variant = 1;
        //let idx = u32::decode(&mut self.de)?;
        let value = seed.deserialize(variant.into_deserializer())?;
        Ok((value, self))
    }

    /// `variant` is called to identify which variant to deserialize.
    ///
    /// This method exists as a convenience for `Deserialize` implementations.
    /// `EnumAccess` implementations should not override the default behavior.
    fn variant<V>(self) -> Result<(V, MyEnumAccess<'a, 'de>)>
    where
        V: Deserialize<'de>,
    {
        log::info!(
            "deserializing {:i$}EnumAccess.variant (not required)",
            "",
            i = self.de.indent()
        );

        self.variant_seed(PhantomData)
    }
}

// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de, 'a> VariantAccess<'de> for MyEnumAccess<'a, 'de> {
    type Error = Error;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    fn unit_variant(self) -> Result<()> {
        log::info!("deserializing {:i$}unit_variant", "", i = self.de.indent());
        Err(Error::ExpectedString)
    }

    // Newtype variants are represented in JSON as `{ NAME: VALUE }` so
    // deserialize the value here.
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        log::info!(
            "deserializing {:i$}newtype_variant_seed",
            "",
            i = self.de.indent()
        );
        seed.deserialize(self.de)
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }` so
    // deserialize the sequence of data here.
    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!("deserializing {:i$}tuple_variant", "", i = self.de.indent());
        de::Deserializer::deserialize_seq(self.de, visitor)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    fn struct_variant<V>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        log::info!(
            "deserializing {:i$}struct_variant",
            "",
            i = self.de.indent()
        );
        de::Deserializer::deserialize_struct(self.de, "", fields, visitor)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_struct() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct Test {
        int: u32,
        seq: Vec<String>,
    }

    let j = r#"{"int":1,"seq":["a","b"]}"#;
    let expected = Test {
        int: 1,
        seq: vec!["a".to_owned(), "b".to_owned()],
    };
    assert_eq!(expected, from_bytes(j).unwrap());
}

#[test]
fn test_enum() {
    #[derive(Deserialize, PartialEq, Debug)]
    enum E {
        Unit,
        Newtype(u32),
        Tuple(u32, u32),
        Struct { a: u32 },
    }

    let j = r#""Unit""#;
    let expected = E::Unit;
    assert_eq!(expected, from_str(j).unwrap());

    let j = r#"{"Newtype":1}"#;
    let expected = E::Newtype(1);
    assert_eq!(expected, from_str(j).unwrap());

    let j = r#"{"Tuple":[1,2]}"#;
    let expected = E::Tuple(1, 2);
    assert_eq!(expected, from_str(j).unwrap());

    let j = r#"{"Struct":{"a":1}}"#;
    let expected = E::Struct { a: 1 };
    assert_eq!(expected, from_str(j).unwrap());
}
