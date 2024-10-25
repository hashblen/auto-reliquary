// This file is generated by rust-protobuf 3.4.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `MKACCPKNCKI.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:MKACCPKNCKI)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct MKACCPKNCKI {
    // message fields
    // @@protoc_insertion_point(field:MKACCPKNCKI.IKCMKIIEBFG)
    pub IKCMKIIEBFG: u32,
    // message oneof groups
    pub POPAJGLCCFF: ::std::option::Option<mkaccpkncki::POPAJGLCCFF>,
    // special fields
    // @@protoc_insertion_point(special_field:MKACCPKNCKI.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a MKACCPKNCKI {
    fn default() -> &'a MKACCPKNCKI {
        <MKACCPKNCKI as ::protobuf::Message>::default_instance()
    }
}

impl MKACCPKNCKI {
    pub fn new() -> MKACCPKNCKI {
        ::std::default::Default::default()
    }

    // .JDOCCKOMOEG GLOAAHIMEHA = 7;

    pub fn GLOAAHIMEHA(&self) -> &super::JDOCCKOMOEG::JDOCCKOMOEG {
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(ref v)) => v,
            _ => <super::JDOCCKOMOEG::JDOCCKOMOEG as ::protobuf::Message>::default_instance(),
        }
    }

    pub fn clear_GLOAAHIMEHA(&mut self) {
        self.POPAJGLCCFF = ::std::option::Option::None;
    }

    pub fn has_GLOAAHIMEHA(&self) -> bool {
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_GLOAAHIMEHA(&mut self, v: super::JDOCCKOMOEG::JDOCCKOMOEG) {
        self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(v))
    }

    // Mutable pointer to the field.
    pub fn mut_GLOAAHIMEHA(&mut self) -> &mut super::JDOCCKOMOEG::JDOCCKOMOEG {
        if let ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(_)) = self.POPAJGLCCFF {
        } else {
            self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(super::JDOCCKOMOEG::JDOCCKOMOEG::new()));
        }
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_GLOAAHIMEHA(&mut self) -> super::JDOCCKOMOEG::JDOCCKOMOEG {
        if self.has_GLOAAHIMEHA() {
            match self.POPAJGLCCFF.take() {
                ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(v)) => v,
                _ => panic!(),
            }
        } else {
            super::JDOCCKOMOEG::JDOCCKOMOEG::new()
        }
    }

    // .MAKKMBLOHHO NALGCLKBBAJ = 4;

    pub fn NALGCLKBBAJ(&self) -> &super::MAKKMBLOHHO::MAKKMBLOHHO {
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(ref v)) => v,
            _ => <super::MAKKMBLOHHO::MAKKMBLOHHO as ::protobuf::Message>::default_instance(),
        }
    }

    pub fn clear_NALGCLKBBAJ(&mut self) {
        self.POPAJGLCCFF = ::std::option::Option::None;
    }

    pub fn has_NALGCLKBBAJ(&self) -> bool {
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_NALGCLKBBAJ(&mut self, v: super::MAKKMBLOHHO::MAKKMBLOHHO) {
        self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(v))
    }

    // Mutable pointer to the field.
    pub fn mut_NALGCLKBBAJ(&mut self) -> &mut super::MAKKMBLOHHO::MAKKMBLOHHO {
        if let ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(_)) = self.POPAJGLCCFF {
        } else {
            self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(super::MAKKMBLOHHO::MAKKMBLOHHO::new()));
        }
        match self.POPAJGLCCFF {
            ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_NALGCLKBBAJ(&mut self) -> super::MAKKMBLOHHO::MAKKMBLOHHO {
        if self.has_NALGCLKBBAJ() {
            match self.POPAJGLCCFF.take() {
                ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(v)) => v,
                _ => panic!(),
            }
        } else {
            super::MAKKMBLOHHO::MAKKMBLOHHO::new()
        }
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(1);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "IKCMKIIEBFG",
            |m: &MKACCPKNCKI| { &m.IKCMKIIEBFG },
            |m: &mut MKACCPKNCKI| { &mut m.IKCMKIIEBFG },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_oneof_message_has_get_mut_set_accessor::<_, super::JDOCCKOMOEG::JDOCCKOMOEG>(
            "GLOAAHIMEHA",
            MKACCPKNCKI::has_GLOAAHIMEHA,
            MKACCPKNCKI::GLOAAHIMEHA,
            MKACCPKNCKI::mut_GLOAAHIMEHA,
            MKACCPKNCKI::set_GLOAAHIMEHA,
        ));
        fields.push(::protobuf::reflect::rt::v2::make_oneof_message_has_get_mut_set_accessor::<_, super::MAKKMBLOHHO::MAKKMBLOHHO>(
            "NALGCLKBBAJ",
            MKACCPKNCKI::has_NALGCLKBBAJ,
            MKACCPKNCKI::NALGCLKBBAJ,
            MKACCPKNCKI::mut_NALGCLKBBAJ,
            MKACCPKNCKI::set_NALGCLKBBAJ,
        ));
        oneofs.push(mkaccpkncki::POPAJGLCCFF::generated_oneof_descriptor_data());
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<MKACCPKNCKI>(
            "MKACCPKNCKI",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for MKACCPKNCKI {
    const NAME: &'static str = "MKACCPKNCKI";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10000 => {
                    self.IKCMKIIEBFG = is.read_uint32()?;
                },
                58 => {
                    self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(is.read_message()?));
                },
                34 => {
                    self.POPAJGLCCFF = ::std::option::Option::Some(mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(is.read_message()?));
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if self.IKCMKIIEBFG != 0 {
            my_size += ::protobuf::rt::uint32_size(1250, self.IKCMKIIEBFG);
        }
        if let ::std::option::Option::Some(ref v) = self.POPAJGLCCFF {
            match v {
                &mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
                },
                &mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.IKCMKIIEBFG != 0 {
            os.write_uint32(1250, self.IKCMKIIEBFG)?;
        }
        if let ::std::option::Option::Some(ref v) = self.POPAJGLCCFF {
            match v {
                &mkaccpkncki::POPAJGLCCFF::GLOAAHIMEHA(ref v) => {
                    ::protobuf::rt::write_message_field_with_cached_size(7, v, os)?;
                },
                &mkaccpkncki::POPAJGLCCFF::NALGCLKBBAJ(ref v) => {
                    ::protobuf::rt::write_message_field_with_cached_size(4, v, os)?;
                },
            };
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> MKACCPKNCKI {
        MKACCPKNCKI::new()
    }

    fn clear(&mut self) {
        self.IKCMKIIEBFG = 0;
        self.POPAJGLCCFF = ::std::option::Option::None;
        self.POPAJGLCCFF = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static MKACCPKNCKI {
        static instance: MKACCPKNCKI = MKACCPKNCKI {
            IKCMKIIEBFG: 0,
            POPAJGLCCFF: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for MKACCPKNCKI {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("MKACCPKNCKI").unwrap()).clone()
    }
}

impl ::std::fmt::Display for MKACCPKNCKI {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for MKACCPKNCKI {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

/// Nested message and enums of message `MKACCPKNCKI`
pub mod mkaccpkncki {

    #[derive(Clone,PartialEq,Debug)]
    #[non_exhaustive]
    // @@protoc_insertion_point(oneof:MKACCPKNCKI.POPAJGLCCFF)
    pub enum POPAJGLCCFF {
        // @@protoc_insertion_point(oneof_field:MKACCPKNCKI.GLOAAHIMEHA)
        GLOAAHIMEHA(super::super::JDOCCKOMOEG::JDOCCKOMOEG),
        // @@protoc_insertion_point(oneof_field:MKACCPKNCKI.NALGCLKBBAJ)
        NALGCLKBBAJ(super::super::MAKKMBLOHHO::MAKKMBLOHHO),
    }

    impl ::protobuf::Oneof for POPAJGLCCFF {
    }

    impl ::protobuf::OneofFull for POPAJGLCCFF {
        fn descriptor() -> ::protobuf::reflect::OneofDescriptor {
            static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::OneofDescriptor> = ::protobuf::rt::Lazy::new();
            descriptor.get(|| <super::MKACCPKNCKI as ::protobuf::MessageFull>::descriptor().oneof_by_name("POPAJGLCCFF").unwrap()).clone()
        }
    }

    impl POPAJGLCCFF {
        pub(in super) fn generated_oneof_descriptor_data() -> ::protobuf::reflect::GeneratedOneofDescriptorData {
            ::protobuf::reflect::GeneratedOneofDescriptorData::new::<POPAJGLCCFF>("POPAJGLCCFF")
        }
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11MKACCPKNCKI.proto\x1a\x11JDOCCKOMOEG.proto\x1a\x11MAKKMBLOHHO.prot\
    o\"\xa3\x01\n\x0bMKACCPKNCKI\x12!\n\x0bIKCMKIIEBFG\x18\xe2\t\x20\x01(\rR\
    \x0bIKCMKIIEBFG\x120\n\x0bGLOAAHIMEHA\x18\x07\x20\x01(\x0b2\x0c.JDOCCKOM\
    OEGH\0R\x0bGLOAAHIMEHA\x120\n\x0bNALGCLKBBAJ\x18\x04\x20\x01(\x0b2\x0c.M\
    AKKMBLOHHOH\0R\x0bNALGCLKBBAJB\r\n\x0bPOPAJGLCCFFb\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(2);
            deps.push(super::JDOCCKOMOEG::file_descriptor().clone());
            deps.push(super::MAKKMBLOHHO::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(MKACCPKNCKI::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}