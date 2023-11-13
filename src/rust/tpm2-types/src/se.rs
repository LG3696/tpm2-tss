use core::panic;
use std::{collections::HashMap, hash::Hash};

use serde::{ser, Serialize};

use crate::error::{Error, Result};
use log;

/// Starting point: https://serde.rs/impl-serializer.html
pub struct Serializer {
    // This byte string starts empty and is appended as values are serialized.
    output: Vec<u8>,
    level: usize,
}

impl Serializer {
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
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
//
// This basic serializer supports only `to_bytes`.
pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: Vec::new(),
        level: 0,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut Serializer {
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // Here we go with the simple methods. The following 12 methods receive one
    // of the primitive types of the data model and map it to JSON by appending
    // into the output string.
    fn serialize_bool(self, v: bool) -> Result<()> {
        log::info!("{:#?}", v);
        let v = v as u8;
        self.serialize_u8(v)
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, v: i8) -> Result<()> {
        log::info!("serializing {:i$} :i8 = {:02x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        log::info!("serializing {:i$} :i16 = {:04x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        log::info!("serializing {:i$} :i32 = {:08x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        log::info!("serializing {:i$} :i64 = {:016x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        log::info!("serializing {:i$} :u8 = {:02x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        log::info!("serializing {:i$} :u16 = {:04x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        log::info!("serializing {:i$} :u32 = {:08x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        log::info!("serializing {:i$} :u64 = {:016x}", "", v, i = self.indent());
        self.output.append(&mut v.to_be_bytes().to_vec());
        Ok(())
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        log::info!("serializing {:i$}f32", "", i = self.indent());
        unimplemented!()
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        log::info!("serializing {:i$}f64", "", i = self.indent());
        unimplemented!()
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    fn serialize_char(self, v: char) -> Result<()> {
        let v = v as u8;
        log::info!("serializing {:i$}char: {:02x}", "", v, i = self.indent());
        self.serialize_u8(v)
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, _v: &str) -> Result<()> {
        log::info!("serializing {:i$}&str", "", i = self.indent());
        unimplemented!()
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        use serde::ser::SerializeSeq;
        log::info!("serializing {:i$}&[u8]", "", i = self.indent());
        let mut seq = self.serialize_seq(Some(v.len()))?;
        for byte in v {
            log::info!("    {:02x}", byte);
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        log::info!("serializing {:i$}None", "", i = self.indent());
        Ok(())
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`. Unfortunately this is typically
    // what people expect when working with JSON. Other formats are encouraged
    // to behave more intelligently if possible.
    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}Some(...)", "", i = self.indent());
        //self.level_push();
        let result = value.serialize(self);
        //self.level_pop();
        result
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        log::info!("serializing {:i$}unit", "", i = self.indent());
        unimplemented!()
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, name: &'static str) -> Result<()> {
        log::info!(
            "serializing {:i$}unit struct {}",
            "",
            name,
            i = self.indent()
        );
        unimplemented!()
    }

    // Unit types are serialized to nothing
    fn serialize_unit_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        log::info!(
            "serializing {:i$}enum variant: unit type {}",
            "",
            name,
            i = self.indent()
        );
        Ok(())
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, name: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!(
            "serializing {:i$}new type struct {}",
            "",
            name,
            i = self.indent()
        );
        unimplemented!()
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to JSON in externally tagged form as `{ NAME: VALUE }`.
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!(
            "serializing {:i$}enum variant: new type {}",
            "",
            name,
            i = self.indent()
        );
        // if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Option<_>>() {
        //     // foo
        // } else {
        // }
        value.serialize(&mut *self)
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start,
    // which in JSON is `[`.
    //
    // The length of the sequence may or may not be known ahead of time. This
    // doesn't make a difference in JSON because the length is not represented
    // explicitly in the serialized form. Some serializers may only be able to
    // support sequences for which the length is known up front.
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        // cast len to u16
        let len = match len {
            Some(len) => match u16::try_from(len) {
                Ok(len) => len,
                Err(_) => {
                    panic!("Error, cannot serialize sequence len as u16: {}", len);
                }
            },
            None => panic!("Error, cannot serialize sequence len: None"),
        };

        // serialize len of sequence as u16
        self.serialize_u16(len)?;
        log::info!("serializing {:i$}sequence[{}]", "", len, i = self.indent());
        Ok(self)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        log::info!("serializing {:i$}tuple[{}]", "", len, i = self.indent());
        unimplemented!()
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        log::info!(
            "serializing {:i$}tuple struct {}[{}]",
            "",
            name,
            len,
            i = self.indent()
        );
        unimplemented!()
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        log::info!(
            "serializing {:i$}enum variant: tuple {}",
            "",
            name,
            i = self.indent()
        );
        Ok(self)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        log::info!("serializing {:i$}map[{:?}]", "", len, i = self.indent());
        Ok(self)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        log::info!(
            "serializing {:i$}struct {}[{}]",
            "",
            name,
            len,
            i = self.indent()
        );
        self.level_push();
        Ok(self)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        log::info!(
            "serializing {:i$}enum variant: struct {}[{}]",
            "",
            name,
            len,
            i = self.indent()
        );
        Ok(self)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a> ser::SerializeSeq for &'a mut Serializer {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}sequence.element", "", i = self.indent());
        self.level_push();
        let result = value.serialize(&mut **self);
        self.level_pop();
        result
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}sequence.end", "", i = self.indent());
        Ok(())
    }
}

impl<'a> ser::SerializeTuple for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}tuple.element", "", i = self.indent());
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}tuple.end", "", i = self.indent());
        Ok(())
    }
}

impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!(
            "serializing {:i$}tuple_struct.element",
            "",
            i = self.indent()
        );
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}tuple_struct.end", "", i = self.indent());
        Ok(())
    }
}

impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!(
            "serializing {:i$}tuple_variant.field",
            "",
            i = self.indent()
        );
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}tuple_variant.end", "", i = self.indent());
        Ok(())
    }
}

impl<'a> ser::SerializeMap for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}map.key", "", i = self.indent());
        unimplemented!()
    }

    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}map.value", "", i = self.indent());
        unimplemented!()
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}map.end", "", i = self.indent());
        unimplemented!()
    }
}

impl<'a> ser::SerializeStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}.{}", "", key, i = self.indent());
        let result = value.serialize(&mut **self);
        result
    }

    fn end(self) -> Result<()> {
        self.level_pop();
        Ok(())
    }
}

impl<'a> ser::SerializeStructVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        log::info!("serializing {:i$}.{}", "", key, i = self.indent());
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::info!("serializing {:i$}struct_variant.end", "", i = self.indent());
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_struct() {
    #[derive(Serialize)]
    struct Test {
        int: u32,
        seq: Vec<u8>,
    }

    let test = Test {
        int: 0xaabbccdd,
        seq: vec![1u8, 2u8, 3u8, 4u8],
    };
    let expected = b"\xaa\xbb\xcc\xdd\x01\x02\x03\x04".to_vec();
    assert_eq!(to_bytes(&test).unwrap(), expected);
}

#[test]
fn test_enum() {
    #[derive(Serialize)]
    #[repr(u16)]
    enum E {
        Unit = 0x0000,
        Newtype(u32) = 0x0001,
        Tuple(u32, u32) = 0x0002,
        Struct { a: u32 } = 0x0003,
    }

    let u = E::Unit;
    let expected = b"".to_vec();
    assert_eq!(to_bytes(&u).unwrap(), expected);

    let n = E::Newtype(0xaabbccdd);
    let expected = b"\xaa\xbb\xcc\xdd".to_vec();
    assert_eq!(to_bytes(&n).unwrap(), expected);

    let t = E::Tuple(0xaabbccdd, 0x00112233);
    let expected = b"\xaa\xbb\xcc\xdd\x00\x11\x22\x33".to_vec();
    assert_eq!(to_bytes(&t).unwrap(), expected);

    let s = E::Struct { a: 0x44556677 };
    let expected = b"\x44\x55\x66\x77".to_vec();
    assert_eq!(to_bytes(&s).unwrap(), expected);
}
